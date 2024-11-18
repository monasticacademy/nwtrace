package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/fatih/color"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// tcpip.Error does not implement error! Need to wrap
type tcpipError struct {
	inner tcpip.Error
}

func (e *tcpipError) Error() string {
	return e.inner.String()
}

type endpointWriter struct {
	ep tcpip.Endpoint
}

func (e *endpointWriter) Write(p []byte) (int, error) {
	var r bytes.Reader
	r.Reset(p)
	n, err := e.ep.Write(&r, tcpip.WriteOptions{})
	if err != nil {
		return int(n), &tcpipError{err}
	}
	if n != int64(len(p)) {
		return int(n), io.ErrShortWrite
	}
	return int(n), nil
}

var isVerbose bool

func verbose(msg string) {
	if isVerbose {
		log.Print(msg)
	}
}

func verbosef(fmt string, parts ...interface{}) {
	if isVerbose {
		log.Printf(fmt, parts...)
	}
}

var errorColor = color.New(color.FgRed, color.Bold)

func errorf(fmt string, parts ...interface{}) {
	if !strings.HasSuffix(fmt, "\n") {
		fmt += "\n"
	}
	errorColor.Printf(fmt, parts...)
}

func Main() error {
	ctx := context.Background()
	_ = ctx

	var args struct {
		Verbose            bool     `arg:"-v,--verbose"`
		NoNewUserNamespace bool     `arg:"--no-new-user-namespace" help:"do not create a new user namespace (must be run as root)"`
		Stderr             bool     `help:"log to stderr (default is stdout)"`
		Tun                string   `default:"httptap" help:"name of the network device to create"`
		Link               string   `default:"10.1.1.100/24" help:"IP address of the network interface that the subprocess will see"`
		Route              string   `default:"0.0.0.0/0" help:"IP address range to route to the internet"`
		Gateway            string   `default:"10.1.1.1" help:"IP address of the gateway that intercepts and proxies network packets"`
		WebUI              string   `help:"address and port to serve API on"`
		User               string   `help:"run command as this user (username or id)"`
		NoOverlay          bool     `arg:"--no-overlay" help:"do not mount any overlay filesystems"`
		Command            []string `arg:"positional"`
		// for the gvisor version
		Address string `arg:"required"`
		Port    uint16
		MAC     string `default:"aa:00:01:01:01:01"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}
	if args.Stderr {
		log.SetOutput(os.Stderr)
	}

	isVerbose = args.Verbose

	// first we re-exec ourselves in a new user namespace
	if os.Args[0] != "/proc/self/exe" && !args.NoNewUserNamespace {
		verbosef("re-execing in a new user namespace...")

		// Here we move to a new user namespace, which is an unpriveleged operation, and which
		// allows us to do everything else we need to do in unpriveleged mode.
		//
		// In a C program, we could run unshare(CLONE_NEWUSER) and directly be in a new user
		// namespace. In a Go program that is not possible because all Go programs are multithreaded
		// (even with GOMAXPROCS=1), and unshare(CLONE_NEWUSER) is only available to single-threaded
		// programs.
		//
		// Our best option is then to launch ourselves in a subprocess that is in a new user namespace,
		// using /proc/self/exe, which contains the executable code for the current process.

		cmd := exec.Command("/proc/self/exe")
		cmd.Args = append([]string{"/proc/self/exe"}, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			}},
			GidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			}},
		}
		err := cmd.Run()
		// if the subprocess exited with an error code then do not print any
		// extra information but do exit with the same code
		if exiterr, ok := err.(*exec.ExitError); ok {
			os.Exit(exiterr.ExitCode())
		}
		if err != nil {
			return fmt.Errorf("error re-exec'ing ourselves in a new user namespace: %w", err)
		}
		return nil
	}

	// lock the OS thread because network and mount namespaces are specific to a single OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// create a new network namespace
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("error creating network namespace: %w", err)
	}

	// create a tun device in the new namespace
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: args.Tun,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating tun device: %w", err)
	}

	// find the link for the device we just created
	link, err := netlink.LinkByName(args.Tun)
	if err != nil {
		return fmt.Errorf("error finding link for new tun device %q: %w", args.Tun, err)
	}

	// bring the link up
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error bringing up link for %q: %w", args.Tun, err)
	}

	// parse the subnet that we will assign to the interface within the namespace
	linksubnet, err := netlink.ParseIPNet(args.Link)
	if err != nil {
		return fmt.Errorf("error parsing subnet: %w", err)
	}

	// assign the address we just parsed to the link, which will change the routing table
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: linksubnet,
	})
	if err != nil {
		return fmt.Errorf("error assign address to tun device: %w", err)
	}

	// parse the subnet that we will route to the tunnel
	routesubnet, err := netlink.ParseIPNet(args.Route)
	if err != nil {
		return fmt.Errorf("error parsing global subnet: %w", err)
	}

	// parse the gateway that we will act as
	gateway := net.ParseIP(args.Gateway)
	if gateway == nil {
		return fmt.Errorf("error parsing gateway: %v", args.Gateway)
	}

	// add a route that sends all traffic going anywhere to our local address
	err = netlink.RouteAdd(&netlink.Route{
		Dst: routesubnet,
		Gw:  gateway,
	})
	if err != nil {
		return fmt.Errorf("error creating default route: %w", err)
	}

	// set up environment variables for the subprocess
	env := append(
		os.Environ(),
		"PS1=HTTPTAP # ",
	)

	// infer mtu using an ioctl
	mtu, err := rawfile.GetMTU(args.Tun)
	if err != nil {
		return fmt.Errorf("error getting MTU: %w", err)
	}

	// create the link endpoint -- this is a small tun2socks addition to the
	// underlying gvisor LinkEndpoint
	tunfd := fmt.Sprintf("%d", tun.ReadWriteCloser.(*os.File).Fd())
	ingress, err := fdbased.Open(tunfd, mtu)
	if err != nil {
		return fmt.Errorf("error creating ")
	}
	_ = ingress

	// create the "tunnel" (connects intercepted TCP connections to a proxy)

	// this is the way to do the above with gvisor directly:
	//
	// linkEP, err := fdbased.New(&fdbased.Options{
	// 	FDs:            []int{int(tunfd)},
	// 	MTU:            mtu,
	// 	EthernetHeader: tun.IsTAP(), // would need to be true for a TAP device
	// 	Address:        tcpip.LinkAddress(maddr),
	// })
	// if err != nil {
	// 	return fmt.Errorf("error creating link from tun device file descriptor: %v", err)
	// }

	// create the network stack and proxy loop
	// stack, err := core.CreateStack(&core.Config{
	// 	LinkEndpoint:     ingress,
	// 	TransportHandler: tunnel.T(),
	// 	MulticastGroups:  multicastGroups,
	// 	Options:          opts,
	// })
	// if err != nil {
	// 	return fmt.Errorf("error creating proxy stack: %w", err)
	// }
	// _ = stack

	verbose("running subcommand now ================")

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// wait for subprocess completion
	err = cmd.Wait()
	if err != nil {
		exitError, isExitError := err.(*exec.ExitError)
		if isExitError {
			return fmt.Errorf("subprocess exited with code %d", exitError.ExitCode())
		} else {
			return fmt.Errorf("error running subprocess: %v", err)
		}
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

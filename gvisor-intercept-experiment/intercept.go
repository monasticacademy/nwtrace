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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
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
		Tun                string   `default:"httptap" help:"name of the network device to create"`
		MAC                string   `default:"aa:00:01:01:01:01" help:"MAC address of the gateway as seen by the subprocess"`
		Link               string   `default:"10.1.1.100/24" help:"IP address of the network interface that the subprocess will see"`
		Route              string   `default:"0.0.0.0/0" help:"IP address range to route to the internet"`
		Gateway            string   `default:"10.1.1.1" help:"IP address of the default gateway seen by the subprocess"`
		NoOverlay          bool     `arg:"--no-overlay" help:"do not mount any overlay filesystems"`
		Command            []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
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
		"HTTPTAP=1",
		"PS1=HTTPTAP # ",
	)

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

	// create the stack with ip and tcp protocols
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// get maximum transmission unit for the tun device
	mtu, err := rawfile.GetMTU(args.Tun)
	if err != nil {
		return fmt.Errorf("error getting MTU: %w", err)
	}

	// get mac address for the tun device
	mac, err := net.ParseMAC(args.MAC)
	if err != nil {
		return fmt.Errorf("error parsing MAC address %q: %v", args.MAC, err)
	}

	// create a link endpoint based on the TUN device
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs:            []int{int(tun.ReadWriteCloser.(*os.File).Fd())},
		MTU:            mtu,
		EthernetHeader: tun.IsTAP(),
		Address:        tcpip.LinkAddress(mac),
	})
	if err != nil {
		return fmt.Errorf("error creating link from tun device file descriptor: %v", err)
	}

	// create and register the TCP forwardedr
	const maxInFlight = 100 // maximum simultaneous connections
	tcpForwarder := tcp.NewForwarder(s, 0, maxInFlight, func(r *tcp.ForwarderRequest) {
		// remote address is the IP address of the subprocess
		// local address is IP address that the subprocess was trying to reach
		log.Printf("at TCP forwarder: %v:%v => %v:%v",
			r.ID().RemoteAddress, r.ID().RemotePort,
			r.ID().LocalAddress, r.ID().LocalPort)

		// send a SYN+ACK in response to the SYN
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("error accepting connection: %v", err)
			r.Complete(true)
			return
		}
		defer r.Complete(false)

		// TODO: set keepalive count, keepalive interval, receive buffer size, send buffer size, like this:
		//   https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L83

		// create an adapter that makes an adapter into a net.Conn
		conn := gonet.NewTCPConn(&wq, ep)
		defer conn.Close()

		fmt.Fprint(conn, "hello gvisor")
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// create the network interface -- tun2socks says this must happen *after* registering the TCP forwarder
	nic := s.NextNICID()
	er := s.CreateNIC(nic, endpoint)
	if er != nil {
		return fmt.Errorf("error creating NIC: %v", er)
	}

	// set promiscuous mode (from tun2socks: https://github.com/xjasonlyu/tun2socks/blob/main/core/nic.go#L43)
	er = s.SetPromiscuousMode(nic, true)
	if er != nil {
		return fmt.Errorf("error setting promiscuous mod: %v", er)
	}

	// set spoofing mode (from tun2socks: https://github.com/xjasonlyu/tun2socks/blob/main/core/nic.go#L56)
	er = s.SetSpoofing(nic, true)
	if er != nil {
		return fmt.Errorf("error setting promiscuous mod: %v", er)
	}

	// set up the route table (without this we will not be able to send packets to the subprocess)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nic,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nic,
		},
	})

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

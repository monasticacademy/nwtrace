package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/joemiller/certin"
	"github.com/monasticacademy/httptap/pkg/bindfiles"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const dumpPacketsToSubprocess = false
const dumpPacketsFromSubprocess = false
const ttl = 10

type AddrPort struct {
	Addr net.IP
	Port uint16
}

func (ap AddrPort) String() string {
	return ap.Addr.String() + ":" + strconv.Itoa(int(ap.Port))
}

// copyToDevice copies packets from a channel to a tun device
func copyToDevice(ctx context.Context, dst *water.Interface, src chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-src:
			_, err := dst.Write(packet)
			if err != nil {
				verbosef("error writing %d bytes to tun: %v, dropping and continuing...", len(packet), err)
			}

			if dumpPacketsToSubprocess {
				reply := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
				verbose(strings.Repeat("\n", 3))
				verbose(strings.Repeat("=", 80))
				verbose("To subprocess:")
				verbose(reply.Dump())
			} else {
				verbosef("transmitting %v raw bytes to subprocess", len(packet))
			}
		}
	}
}

// layernames makes a one-line list of layers in a packet
func layernames(packet gopacket.Packet) []string {
	var s []string
	for _, layer := range packet.Layers() {
		s = append(s, layer.LayerType().String())
	}
	return s
}

// write an X.509 certificate to a .pem or .crt file
func writeCertFile(cert []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error opening pem file for writing: %w", err)
	}
	defer f.Close()

	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return fmt.Errorf("error encoding CA to pem: %w", err)
	}

	verbosef("created %v", path)
	return nil
}

var isVerbose bool

func verbose(msg string) {
	if isVerbose {
		log.Print(msg)
	}
}

func verbosef(fmt string, parts ...interface{}) {
	if isVerbose {
		verbosef(fmt, parts...)
	}
}

func Main() error {
	ctx := context.Background()
	var args struct {
		Verbose bool     `arg:"-v,--verbose"`
		Tun     string   `default:"httptap"`
		Link    string   `default:"10.1.1.100/24"`
		Route   string   `default:"0.0.0.0/0"`
		Gateway string   `default:"10.1.1.1"`
		User    string   `help:"run command as this user (username or id)"`
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	isVerbose = args.Verbose

	// save the working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current working directory: %w", err)
	}
	_ = cwd

	// generate a root CA
	ca, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true})
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}

	// write the certificate authority to a temporary file
	caPath := "/tmp/httptap.cert"
	err = writeCertFile(ca.Certificate.Raw, caPath)
	if err != nil {
		return err
	}

	// lock the OS thread because network and mount namespaces are specific to a single OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// save a reference to our initial network namespace so we can get back
	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("error getting initial network namespace: %w", err)
	}
	defer origns.Close()

	// create a new network namespace
	newns, err := netns.New()
	if err != nil {
		return fmt.Errorf("error creating network namespace: %w", err)
	}
	defer newns.Close()

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

	// overlay resolv.conf
	resolvConf := fmt.Sprintf("nameserver %s\n", args.Gateway)
	mount, err := bindfiles.Mount(bindfiles.File("/etc/resolv.conf", []byte(resolvConf)))
	if err != nil {
		return fmt.Errorf("error setting up overlay: %w", err)
	}
	defer mount.Remove()

	// switch user and group if requested
	if args.User != "" {
		u, err := user.Lookup(args.User)
		if err != nil {
			return fmt.Errorf("error looking up user %q: %w", args.User, err)
		}

		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("error parsing user id %q as a number: %w", u.Uid, err)
		}

		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			return fmt.Errorf("error parsing group id %q as a number: %w", u.Gid, err)
		}

		// there are three (!) user/group IDs for a process: the real, effective, and saved
		// they have the purpose of allowing the process to go "back" to them
		// here we set just the effective, which, when you are root, sets all three

		err = unix.Setgid(gid)
		if err != nil {
			return fmt.Errorf("error switching to group %q (gid %v): %w", args.User, gid, err)
		}

		err = unix.Setuid(uid)
		if err != nil {
			return fmt.Errorf("error switching to user %q (uid %v): %w", args.User, uid, err)
		}

		verbosef("now in uid %d, gid %d", unix.Getuid(), unix.Getgid())
	}

	// create environment for the subprocess
	env := append(
		os.Environ(),
		"PS1=HTTPTAP # ",
		"HTTPTAP=1",
		"CURL_CA_BUNDLE="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"SSL_CERT_FILE="+caPath,
	)
	verbose("running subcommand now ================")

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Dir = cwd // pivot_root will have changed our work dir to /old/...
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// create a goroutine to facilitate sending packets to the process
	toSubprocess := make(chan []byte, 1000)
	go copyToDevice(ctx, tun, toSubprocess)

	// start a goroutine to process packets from the subprocess -- this will be killed
	// when the subprocess completes
	verbosef("listening on %v", args.Tun)
	go func() {
		// instantiate the tcp and udp stacks
		tcpstack := newTCPStack(toSubprocess)
		udpstack := newUDPStack(toSubprocess)

		// handle DNS queries by calling net.Resolve
		udpstack.HandleFunc(":53", func(w udpResponder, p *udpPacket) {
			handleDNS(context.Background(), w, p.payload)
		})

		// TODO: proxy all other UDP packets to the public internet
		// go proxyUDP(udppstack.Listen("*"))

		// intercept all https connections on port 443
		go proxyHTTPS(tcpstack.Listen(":443"), ca)

		// start listening for TCP connections and proxy each one to the world
		go proxyTCP(tcpstack.Listen("*"))

		// start reading raw bytes from the tunnel device and sending them to the appropriate stack
		buf := make([]byte, 1500)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				verbosef("error reading a packet from tun: %v, ignoring", err)
				continue
			}

			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
			ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok {
				continue
			}

			tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			if !isTCP && !isUDP {
				continue
			}

			if dumpPacketsFromSubprocess {
				verbose(strings.Repeat("\n", 3))
				verbose(strings.Repeat("=", 80))
				verbose("From subprocess:")
				verbose(packet.Dump())
			}

			if isTCP {
				verbosef("received from subprocess: %v", onelineTCP(ipv4, tcp, tcp.Payload))
				tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
			}
			if isUDP {
				verbosef("received from subprocess: %v", onelineUDP(ipv4, udp, udp.Payload))
				udpstack.handlePacket(ipv4, udp, udp.Payload)
			}
		}
	}()

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

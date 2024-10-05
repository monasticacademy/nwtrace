package main

import (
	"context"
	"fmt"
	"io"
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

type TCPState int

const (
	StateInit TCPState = iota + 1
	StateSynchronizing
	StateConnected
	StateFinished
)

type stream struct {
	protocol       string // can be "tcp" or "udp"
	world          AddrPort
	fromSubprocess chan []byte // from the subprocess to the world
	toSubprocess   io.Writer   // application-level payloads are written here, and IP packets get sent

	subprocess   AddrPort
	serializeBuf gopacket.SerializeBuffer

	// tcp-specific things (TODO: factor out)
	state TCPState
	seq   uint32 // sequence number for packets going to the subprocess
	ack   uint32 // the next acknowledgement number to send
}

func newStream(protool string, world AddrPort, subprocess AddrPort) *stream {
	stream := stream{
		protocol:       protool,
		world:          world,
		subprocess:     subprocess,
		state:          StateInit,
		fromSubprocess: make(chan []byte, 1024),
		serializeBuf:   gopacket.NewSerializeBuffer(),
	}

	return &stream
}

func (s *stream) deliverToApplication(payload []byte) {
	// copy the payload because it may be overwritten before the write loop gets to it
	cp := make([]byte, len(payload))
	copy(cp, payload)

	log.Printf("stream enqueing %d bytes to send to world", len(payload))

	// send to channel unless it would block
	select {
	case s.fromSubprocess <- cp:
	default:
		log.Printf("channel to world would block, dropping %d bytes", len(payload))
	}
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
				log.Printf("error writing %d bytes to tun: %v, dropping and continuing...", len(packet), err)
			}

			if dumpPacketsToSubprocess {
				reply := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
				log.Println(strings.Repeat("\n", 3))
				log.Println(strings.Repeat("=", 80))
				log.Println("To subprocess:")
				log.Println(reply.Dump())
			} else {
				log.Printf("transmitting %v raw bytes to subprocess", len(packet))
			}
		}
	}
}

// serializeTCP serializes a TCP packet
func serializeTCP(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte, tmp gopacket.SerializeBuffer) ([]byte, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tmp.Clear()

	// each layer is *prepended*, treating the current buffer data as payload
	p, err := tmp.AppendBytes(len(payload))
	if err != nil {
		return nil, fmt.Errorf("error appending TCP payload to packet (%d bytes): %w", len(payload), err)
	}
	copy(p, payload)

	err = tcp.SerializeTo(tmp, opts)
	if err != nil {
		return nil, fmt.Errorf("error serializing TCP part of packet: %w", err)
	}

	err = ipv4.SerializeTo(tmp, opts)
	if err != nil {
		log.Printf("error serializing IP part of packet: %v", err)
	}

	return tmp.Bytes(), nil
}

// serializeUDP serializes a UDP packet
func serializeUDP(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte, tmp gopacket.SerializeBuffer) ([]byte, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tmp.Clear()

	// each layer is *prepended*, treating the current buffer data as payload
	p, err := tmp.AppendBytes(len(payload))
	if err != nil {
		return nil, fmt.Errorf("error appending TCP payload to packet (%d bytes): %w", len(payload), err)
	}
	copy(p, payload)

	err = udp.SerializeTo(tmp, opts)
	if err != nil {
		return nil, fmt.Errorf("error serializing TCP part of packet: %w", err)
	}

	err = ipv4.SerializeTo(tmp, opts)
	if err != nil {
		log.Printf("error serializing IP part of packet: %v", err)
	}

	return tmp.Bytes(), nil
}

// preview returns the first 100 bytes or first line of its input, whichever is shorter
func preview(b []byte) string {
	s := string(b)
	pos := strings.Index(s, "\n")
	if pos >= 0 {
		s = s[:pos] + "..."
	}
	if len(s) > 100 {
		s = s[:100] + "..."
	}
	return s
}

// layernames makes a one-line list of layers in a packet
func layernames(packet gopacket.Packet) []string {
	var s []string
	for _, layer := range packet.Layers() {
		s = append(s, layer.LayerType().String())
	}
	return s
}

func onelineTCP(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) string {
	var flags []string
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	if tcp.NS {
		flags = append(flags, "NS")
	}
	// ignore PSH flag

	flagstr := strings.Join(flags, "+")
	return fmt.Sprintf("TCP %v:%d => %v:%d %s - Seq %d - Ack %d - Len %d",
		ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort, flagstr, tcp.Seq, tcp.Ack, len(tcp.Payload))
}

func onelineUDP(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) string {
	return fmt.Sprintf("UDP %v:%d => %v:%d - Len %d",
		ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort, len(udp.Payload))
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

	// save the working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current working directory: %w", err)
	}
	_ = cwd

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

	// switch user and group id if requested
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
		_ = gid

		// there are three (!) user/group IDs for a process: the real, effective, and saved
		// they have the purpose of allowing the process to go "back" to them
		// here we set all three of them

		err = unix.Setgid(gid)
		if err != nil {
			log.Printf("error switching to group %q (gid %v): %v", args.User, gid, err)
		}

		//err = unix.Setresuid(uid, uid, uid)
		err = unix.Setuid(uid)
		if err != nil {
			log.Printf("error switching to user %q (uid %v): %v", args.User, uid, err)
		}

		log.Printf("now in uid %d, gid %d", unix.Getuid(), unix.Getgid())

		// err = unix.Setresgid(gid, gid, gid)
		// if err != nil {
		// 	log.Printf("error switching to group for user %q (gid %v): %v", args.User, gid, err)
		// }
	}

	log.Println("running subcommand now ================")

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Dir = cwd // pivot_root will have changed our work dir to /old/...
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "PS1=HTTPTAP # ", "HTTPTAP=1")
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// create a goroutine to facilitate sending packets to the process
	toSubprocess := make(chan []byte, 1000)
	go copyToDevice(ctx, tun, toSubprocess)

	// start a goroutine to process packets from the subprocess -- this will be killed
	// when the subprocess completes
	log.Printf("listening on %v", args.Tun)
	go func() {
		// instantiate the tcp and udp stacks
		tcpstack := newTCPStack(toSubprocess)
		udpstack := newUDPStack(toSubprocess)

		// start listening for DNS connections and service each one by calling net.Resolve
		go serviceDNS(udpstack.Listen(":53"))

		// start listening for TCP connections and proxy each one to the world
		go proxyTCP(tcpstack.Listen("*"))

		// start listening for UDP connections and proxy each one to the world
		go proxyUDP(udpstack.Listen("*"))

		// start reading raw bytes from the tunnel device and sending them to the appropriate stack
		buf := make([]byte, 1500)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				log.Printf("error reading a packet from tun: %v, ignoring", err)
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
				log.Println(strings.Repeat("\n", 3))
				log.Println(strings.Repeat("=", 80))
				log.Println("From subprocess:")
				log.Println(packet.Dump())
			}

			if isTCP {
				log.Printf("received from subprocess: %v", onelineTCP(ipv4, tcp, tcp.Payload))
				tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
			}
			if isUDP {
				log.Printf("received from subprocess: %v", onelineUDP(ipv4, udp, udp.Payload))
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

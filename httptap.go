package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/alexflint/go-arg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/monasticacademy/httptap/pkg/overlayroot"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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
	fromSubprocess chan []byte  // from the subprocess to the world
	toSubprocess   func([]byte) // in means from the world to the subprocess

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

func (s *stream) sendToWorld(payload []byte) {
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

func (s *stream) dial() {
	conn, err := net.Dial(s.protocol, s.world.String())
	if err != nil {
		log.Printf("service loop exited with error: %v", err)
		return
	}

	go s.copyToSubprocess(s.toSubprocess, conn)
	go s.copyToWorld(conn, s.fromSubprocess)
}

func (s *stream) copyToSubprocess(toSubprocess func([]byte), fromWorld net.Conn) {
	buf := make([]byte, 1<<20)
	for {
		n, err := fromWorld.Read(buf)
		if err == io.EOF {
			// how to indicate to outside world that we're done?
			return
		}
		if err != nil {
			// how to indicate to outside world that the read failed?
			return
		}

		// copy the data
		cp := make([]byte, n)
		copy(cp, buf)

		// send packet to channel, drop if it would block
		toSubprocess(cp)
	}
}

func (s *stream) copyToWorld(toWorld net.Conn, fromSubprocess chan []byte) {
	for packet := range fromSubprocess {
		log.Printf("stream writing %d bytes (%q) to world connection", len(packet), preview(packet))
		_, err := toWorld.Write(packet)

		if err != nil {
			// how to indicate to outside world that the write failed?
			log.Printf("failed to write %d bytes from subprocess to world: %v", len(packet), err)
			return
		}
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
func layernames(packet gopacket.Packet) string {
	var s []string
	for _, layer := range packet.Layers() {
		s = append(s, layer.LayerType().String())
	}
	return strings.Join(s, " ")
}

// oneline makes a one-line summary of a tcp packet
func oneline(packet gopacket.Packet) string {
	ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return fmt.Sprintf("<not an IPv4 packet (has %v)>", layernames(packet))
	}

	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return fmt.Sprintf("<not a TCP packet (has %v)>", layernames(packet))
	}

	return onelineTCP(ipv4, tcp, tcp.Payload)
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

// TCP stack

type tcpStack struct {
	streamsBySrcDst map[string]*stream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet
}

func newTCPStack(toSubprocess chan []byte) *tcpStack {
	return &tcpStack{
		streamsBySrcDst: make(map[string]*stream),
		toSubprocess:    toSubprocess,
	}
}

func (s *tcpStack) handlePacket(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) {
	// it happens that a process will connect to the same remote service multiple times in from
	// different source ports so we must key by a descriptor that includes both endpoints
	dst := AddrPort{Addr: ipv4.DstIP, Port: uint16(tcp.DstPort)}
	src := AddrPort{Addr: ipv4.SrcIP, Port: uint16(tcp.SrcPort)}

	// put source address, source port, destination address, and destination port into a human-readable string
	srcdst := src.String() + " => " + dst.String()
	stream, found := s.streamsBySrcDst[srcdst]
	if !found {
		// create a new stream no matter what kind of packet this is
		// later we will reject everything other than SYN packets sent to a fresh stream
		stream = newStream("tcp", dst, src)

		// define the function that wraps payloads in TCP and IP headers
		stream.toSubprocess = func(payload []byte) {
			sz := uint32(len(payload))

			replytcp := layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				Seq:     atomic.AddUint32(&stream.seq, sz) - sz, // sequence number on our side
				Ack:     atomic.LoadUint32(&stream.ack),         // laste sequence number we saw on their side
				ACK:     true,                                   // this indicates that we are acknolwedging some bytes
				Window:  64240,                                  // number of bytes we are willing to receive (copied from sender)
			}

			replyipv4 := layers.IPv4{
				Version:  4, // indicates IPv4
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    ipv4.DstIP,
				DstIP:    ipv4.SrcIP,
			}

			replytcp.SetNetworkLayerForChecksum(&replyipv4)

			// log
			log.Printf("sending tcp to subprocess (payload): %s", onelineTCP(&replyipv4, &replytcp, payload))

			// serialize the data
			packet, err := serializeTCP(&replyipv4, &replytcp, payload, stream.serializeBuf)
			if err != nil {
				log.Printf("error serializing TCP packet: %v, ignoring", err)
				return
			}

			// make a copy because the same buffer will be re-used
			cp := make([]byte, len(packet))
			copy(cp, packet)

			// send to the subprocess channel non-blocking
			select {
			case s.toSubprocess <- cp:
			default:
				log.Printf("channel for sending tcp to subprocess would have blocked, dropping %d bytes", len(cp))
			}
		}

		s.streamsBySrcDst[srcdst] = stream
	}

	// handle connection establishment
	if tcp.SYN && stream.state == StateInit {
		stream.state = StateSynchronizing
		seq := atomic.AddUint32(&stream.seq, 1) - 1
		atomic.StoreUint32(&stream.ack, tcp.Seq+1)
		log.Printf("got SYN to %v:%v, now state is %v", ipv4.DstIP, tcp.DstPort, stream.state)

		// dial the outside world
		go stream.dial()

		// reply to the subprocess as if the connection were already good to go
		replytcp := layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			SYN:     true,
			ACK:     true,
			Seq:     seq,
			Ack:     tcp.Seq + 1,
			Window:  64240, // number of bytes we are willing to receive (copied from sender)
		}

		replyipv4 := layers.IPv4{
			Version:  4, // indicates IPv4
			TTL:      ttl,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    ipv4.DstIP,
			DstIP:    ipv4.SrcIP,
		}

		replytcp.SetNetworkLayerForChecksum(&replyipv4)

		// log
		log.Printf("sending tcp to subprocess (synack): %s", onelineTCP(&replyipv4, &replytcp, nil))

		// serialize the packet
		serialized, err := serializeTCP(&replyipv4, &replytcp, nil, stream.serializeBuf)
		if err != nil {
			log.Printf("error serializing reply TCP: %v, dropping", err)
			return
		}

		// make a copy of the data
		cp := make([]byte, len(serialized))
		copy(cp, serialized)

		// send to the channel that goes to the subprocess
		select {
		case s.toSubprocess <- cp:
		default:
			log.Printf("channel for sending to subprocess would have blocked, dropping %d bytes", len(cp))
		}
	}

	if tcp.ACK && stream.state == StateSynchronizing {
		stream.state = StateConnected
		log.Printf("got ACK to %v:%v, now state is %v", ipv4.DstIP, tcp.DstPort, stream.state)

		// nothing more to do here -- if there is a payload then it will be forwarded
		// to the subprocess in the block below
	}

	// payload packets will often have ACK set, which acknowledges previously sent bytes
	if !tcp.SYN && len(tcp.Payload) > 0 && stream.state == StateConnected {
		log.Printf("got %d tcp bytes to %v:%v (%q), forwarding to world", len(tcp.Payload), ipv4.DstIP, tcp.DstPort, preview(tcp.Payload))

		// update sequence number
		atomic.StoreUint32(&stream.ack, tcp.Seq+uint32(len(tcp.Payload)))

		// forward the data to the world
		stream.sendToWorld(tcp.Payload)
	}
}

// UDP stack

type udpStack struct {
	streamsBySrcDst map[string]*stream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet
}

func newUDPStack(toSubprocess chan []byte) *udpStack {
	return &udpStack{
		streamsBySrcDst: make(map[string]*stream),
		toSubprocess:    toSubprocess,
	}
}

func (s *udpStack) handlePacket(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) {
	// it happens that a process will connect to the same remote service multiple times in from
	// different source ports so we must key by a descriptor that includes both endpoints
	dst := AddrPort{Addr: ipv4.DstIP, Port: uint16(udp.DstPort)}
	src := AddrPort{Addr: ipv4.SrcIP, Port: uint16(udp.SrcPort)}

	// put source address, source port, destination address, and destination port into a human-readable string
	srcdst := src.String() + " => " + dst.String()
	stream, found := s.streamsBySrcDst[srcdst]
	if !found {
		// create a new stream no matter what kind of packet this is
		// later we will reject everything other than SYN packets sent to a fresh stream
		stream = newStream("udp", dst, src)

		// define the function that wraps payloads in TCP and IP headers
		stream.toSubprocess = func(payload []byte) {
			replyudp := layers.UDP{
				SrcPort: udp.DstPort,
				DstPort: udp.SrcPort,
			}

			replyipv4 := layers.IPv4{
				Version:  4, // indicates IPv4
				TTL:      ttl,
				Protocol: layers.IPProtocolUDP,
				SrcIP:    ipv4.DstIP,
				DstIP:    ipv4.SrcIP,
			}

			replyudp.SetNetworkLayerForChecksum(&replyipv4)

			// log
			log.Printf("sending udp to subprocess (payload): %s", onelineUDP(&replyipv4, &replyudp, payload))

			// serialize the data
			packet, err := serializeUDP(&replyipv4, &replyudp, payload, stream.serializeBuf)
			if err != nil {
				log.Printf("error serializing UDP packet: %v, ignoring", err)
				return
			}

			// make a copy because the same buffer will be re-used
			cp := make([]byte, len(packet))
			copy(cp, packet)

			// send to the subprocess channel non-blocking
			select {
			case s.toSubprocess <- cp:
			default:
				log.Printf("channel for sending udp to subprocess would have blocked, dropping %d bytes", len(cp))
			}
		}

		go stream.dial()

		s.streamsBySrcDst[srcdst] = stream
	}

	// forward the data to the world
	log.Printf("got %d udp bytes to %v:%v (%q), forwarding to world", len(udp.Payload), ipv4.DstIP, udp.DstPort, preview(udp.Payload))
	stream.sendToWorld(udp.Payload)
}

func Main() error {
	ctx := context.Background()
	var args struct {
		Tun     string   `default:"httptap"`
		Link    string   `default:"10.1.1.100/24"`
		Route   string   `default:"0.0.0.0/0"`
		Gateway string   `default:"10.1.1.1"`
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	// lock the OS thread in order to switch network namespaces (network namespaces are thread-specific)
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
		log.Fatal(err)
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
	//resolvConf := fmt.Sprintf("nameserver %v\n", args.Gateway)
	resolvConf := "nameserver 1.1.1.1\n"
	mount, err := overlayroot.Pivot(overlayroot.File("/etc/resolv.conf", []byte(resolvConf)))
	if err != nil {
		return fmt.Errorf("error setting up overlay: %w", err)
	}
	defer mount.Remove()

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PS1=HTTPTAP # "}
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
		// all our tcp streams, keyed by source address, source port, destination address, and destination port
		tcpstack := newTCPStack(toSubprocess)
		udpstack := newUDPStack(toSubprocess)

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
			} else {
				log.Printf("received from subprocess: %v", oneline(packet))
			}

			if isTCP {
				tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
			}
			if isUDP {
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

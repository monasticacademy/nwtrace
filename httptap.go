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
	"sync"
	"sync/atomic"

	"github.com/alexflint/go-arg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
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

// TCP stack

type tcpStack struct {
	streamsBySrcDst map[string]*stream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet

	listenerMu sync.Mutex
	listeners  []*tcpListener
}

func newTCPStack(toSubprocess chan []byte) *tcpStack {
	return &tcpStack{
		streamsBySrcDst: make(map[string]*stream),
		toSubprocess:    toSubprocess,
	}
}

// tcpListener is the interface for the application to intercept TCP connections
type tcpListener struct {
	pattern     string
	connections chan *stream // the tcpStack sends streams here when they are created and they match the pattern above
}

// Accept accepts an intercepted connection. Later this will implement net.Listener.Accept
func (l *tcpListener) Accept() (*stream, error) {
	stream := <-l.connections
	if stream == nil {
		// this means the channel is closed, which means the tcpStack was shut down
		return nil, net.ErrClosed
	}
	return stream, nil
}

// Listen returns a stream when a new stream is created.
//
// Pattern can a hostname, a :port, a hostname:port, or "*" for everything". For example:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
//
// Later this will be like net.Listen
func (s *tcpStack) Listen(pattern string) *tcpListener {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	listener := tcpListener{pattern: pattern, connections: make(chan *stream, 64)}
	s.listeners = append(s.listeners, &listener)
	return &listener
}

// notifyListeners is called when a new TCP stream is created. It finds the first listener
// that will accept the given stream. It never blocks.
func (s *tcpStack) notifyListeners(stream *stream) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	for _, listener := range s.listeners {
		// for now, always send it to the first listener that is ready
		select {
		case listener.connections <- stream:
			return
		default:
		}
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
		stream.toSubprocess = &tcpWriter{
			theirIP:   ipv4.SrcIP,
			ourIP:     ipv4.DstIP,
			theirPort: tcp.SrcPort,
			ourPort:   tcp.DstPort,
			buf:       stream.serializeBuf,
			out:       s.toSubprocess,
			stream:    stream,
		}

		s.streamsBySrcDst[srcdst] = stream

		s.notifyListeners(stream)
	}

	// handle connection establishment
	if tcp.SYN && stream.state == StateInit {
		stream.state = StateSynchronizing
		seq := atomic.AddUint32(&stream.seq, 1) - 1
		atomic.StoreUint32(&stream.ack, tcp.Seq+1)
		log.Printf("got SYN to %v:%v, now state is %v", ipv4.DstIP, tcp.DstPort, stream.state)

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
		log.Printf("sending SYN+ACK to subprocess: %s", onelineTCP(&replyipv4, &replytcp, nil))

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

	// handle connection establishment
	if tcp.FIN && stream.state != StateInit {
		// we should not send any more packets after we send our own FIN, but we can
		// always safely ack the other side FIN
		stream.state = StateFinished
		seq := atomic.AddUint32(&stream.seq, 1) - 1
		atomic.StoreUint32(&stream.ack, tcp.Seq+1)
		log.Printf("got FIN to %v:%v, now state is %v", ipv4.DstIP, tcp.DstPort, stream.state)

		// make a FIN+ACK reply to send to the subprocess
		replytcp := layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			FIN:     true,
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
		log.Printf("sending FIN+ACK to subprocess: %s", onelineTCP(&replyipv4, &replytcp, nil))

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

// when you write to tcpWriter, it sends a raw TCP packet containing what you wrote to an
// underlying channel
type tcpWriter struct {
	ourIP     net.IP                   // IP address that we are acting as in this connection (not necessarily our real IP)
	theirIP   net.IP                   // IP address that other side (the subprocess) considers to be theirs
	ourPort   layers.TCPPort           // port that we will put as "source port" on packets we send (not necessarily really ours)
	theirPort layers.TCPPort           // port that other side (the subprocess) considers to be theirs
	out       chan []byte              // we send raw IP packets to this channel in order to transmit
	buf       gopacket.SerializeBuffer // buffer used to serialize packets
	stream    *stream
}

func (w *tcpWriter) Write(payload []byte) (int, error) {
	sz := uint32(len(payload))

	replytcp := layers.TCP{
		SrcPort: w.ourPort,
		DstPort: w.theirPort,
		Seq:     atomic.AddUint32(&w.stream.seq, sz) - sz, // sequence number on our side
		Ack:     atomic.LoadUint32(&w.stream.ack),         // laste sequence number we saw on their side
		ACK:     true,                                     // this indicates that we are acknolwedging some bytes
		Window:  64240,                                    // number of bytes we are willing to receive (copied from sender)
	}

	replyipv4 := layers.IPv4{
		Version:  4, // indicates IPv4
		TTL:      ttl,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    w.ourIP,
		DstIP:    w.theirIP,
	}

	replytcp.SetNetworkLayerForChecksum(&replyipv4)

	// log
	log.Printf("sending tcp packet to subprocess: %s", onelineTCP(&replyipv4, &replytcp, payload))

	// serialize the data
	packet, err := serializeTCP(&replyipv4, &replytcp, payload, w.buf)
	if err != nil {
		return 0, fmt.Errorf("error serializing TCP packet: %w", err)
	}

	// make a copy because the same buffer will be re-used
	cp := make([]byte, len(packet))
	copy(cp, packet)

	// send to the subprocess channel non-blocking
	select {
	case w.out <- cp:
	default:
		return 0, fmt.Errorf("channel would have blocked")
	}

	// return number of bytes sent to us, not number of bytes written to underlying network
	return len(payload), nil
}

// UDP stack

type udpStack struct {
	streamsBySrcDst map[string]*stream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet

	// packets to this dns server+port are intercepted and replied to directly
	dnsServer string
	dnsPort   layers.UDPPort
}

func newUDPStack(toSubprocess chan []byte) *udpStack {
	return &udpStack{
		streamsBySrcDst: make(map[string]*stream),
		toSubprocess:    toSubprocess,
		dnsServer:       "10.1.1.1",
		dnsPort:         layers.UDPPort(53),
	}
}

// when you write to udpWriter, it sends a raw TCP packet containing what you wrote to an
// underlying channel
type udpWriter struct {
	ourIP     net.IP                   // IP address that we are acting as in this connection (not necessarily our real IP)
	theirIP   net.IP                   // IP address that other side (the subprocess) considers to be theirs
	ourPort   layers.UDPPort           // port that we will put as "source port" on packets we send (not necessarily really ours)
	theirPort layers.UDPPort           // port that other side (the subprocess) considers to be theirs
	out       chan []byte              // we send raw IP packets to this channel in order to transmit
	buf       gopacket.SerializeBuffer // buffer used to serialize packets
}

func (w *udpWriter) Write(payload []byte) (int, error) {
	replyudp := layers.UDP{
		SrcPort: w.ourPort,
		DstPort: w.theirPort,
	}

	replyipv4 := layers.IPv4{
		Version:  4, // indicates IPv4
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    w.ourIP,
		DstIP:    w.theirIP,
	}

	replyudp.SetNetworkLayerForChecksum(&replyipv4)

	// log
	log.Printf("sending udp packet to subprocess: %s", onelineUDP(&replyipv4, &replyudp, payload))

	// serialize the data
	packet, err := serializeUDP(&replyipv4, &replyudp, payload, w.buf)
	if err != nil {
		return 0, fmt.Errorf("error serializing UDP packet: %w", err)
	}

	// make a copy because the same buffer will be re-used
	cp := make([]byte, len(packet))
	copy(cp, packet)

	// send to the subprocess channel non-blocking
	select {
	case w.out <- cp:
	default:
		return 0, fmt.Errorf("channel for sending udp to subprocess would have blocked")
	}

	// return number of bytes passed in, not number of bytes sent to output
	return len(payload), nil
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
		stream.toSubprocess = &udpWriter{
			ourIP:     ipv4.DstIP,
			theirIP:   ipv4.SrcIP,
			ourPort:   udp.DstPort,
			theirPort: udp.SrcPort,
			buf:       stream.serializeBuf,
			out:       s.toSubprocess,
		}

		go proxyUDPConn(stream)

		s.streamsBySrcDst[srcdst] = stream
	}

	// if the packet is dns to the gateway then intercept and respond directly
	if ipv4.DstIP.String() == s.dnsServer && udp.DstPort == s.dnsPort {
		log.Printf("got a %d-byte dns packet to %v:%v (%q), responding directly", len(udp.Payload), ipv4.DstIP, udp.DstPort, preview(udp.Payload))
		go stream.handleDNS(context.Background(), stream.toSubprocess, udp.Payload)
		return
	}

	// forward the data to the world
	log.Printf("got %d udp bytes to %v:%v (%q), forwarding to world", len(udp.Payload), ipv4.DstIP, udp.DstPort, preview(udp.Payload))
	stream.sendToWorld(udp.Payload)
}

// handle DNS directly -- payload here is the application-level UDP payload
func (s *stream) handleDNS(ctx context.Context, w io.Writer, payload []byte) {
	var req dns.Msg
	err := req.Unpack(payload)
	if err != nil {
		log.Printf("error unpacking dns packet: %v, ignoring", err)
		return
	}

	if req.Opcode != dns.OpcodeQuery {
		log.Printf("ignoring a dns query with non-query opcode (%v)", req.Opcode)
		return
	}

	// resolve the query
	rrs, err := handleDNSQuery(ctx, &req)
	if err != nil {
		log.Printf("dns failed for %v with error: %v, sending a response with empty answer", req, err.Error())
		// do not abort here, continue on and send a reply with no answer
		// because the client might easily have tried to resolve a non-existent
		// hostname
	}

	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.Answer = rrs

	// serialize the response
	buf, err := resp.Pack()
	if err != nil {
		log.Printf("error serializing dns response: %v, abandoning...", err)
		return
	}

	// always send the entire buffer in a single Write() since UDP writes one packet per call to Write()
	_, err = w.Write(buf)
	if err != nil {
		log.Printf("error writing dns response: %v, abandoning...", err)
		return
	}
}

// handleDNSQuery resolves IPv4 hostnames according to net.DefaultResolver
func handleDNSQuery(ctx context.Context, req *dns.Msg) ([]dns.RR, error) {
	const upstreamDNS = "1.1.1.1:53" // TODO: get from resolv.conf and nsswitch.conf

	if len(req.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := req.Question[0]
	log.Printf("got dns request for %v", question.Name)

	// handle the request ourselves
	switch question.Qtype {
	case dns.TypeA:
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", question.Name)
		if err != nil {
			return nil, fmt.Errorf("the default resolver said: %w", err)
		}

		var rrs []dns.RR
		for _, ip := range ips {
			rrline := fmt.Sprintf("%s A %s", question.Name, ip)
			rr, err := dns.NewRR(rrline)
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}
		return rrs, nil
	}

	log.Println("proxying the request...")

	// proxy the request to another server
	request := new(dns.Msg)
	req.CopyTo(request)
	request.Question = []dns.Question{question}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(request, upstreamDNS)
	if err != nil {
		return nil, err
	}

	log.Printf("got answer from upstream dns server with %d answers", len(response.Answer))

	if len(response.Answer) > 0 {
		return response.Answer, nil
	}
	return nil, fmt.Errorf("not found")
}

// proxyTCP accepts connections on the given listener. For each one it dials the outside world
// and proxies data back and forth. It blocks until the listener returns an error, which only
// happens when the TCP stack shuts down.
func proxyTCP(l *tcpListener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("listener.Accept returned with error: %w", err)
		}

		// dial will take a while to complete; do not block on next accept
		go proxyTCPConn(conn)
	}
}

// proxyTCPConn proxies data received on one TCP connection to the world, and back the other way.
func proxyTCPConn(s *stream) {
	conn, err := net.Dial("tcp", s.world.String())
	if err != nil {
		log.Printf("service loop exited with error: %v", err)
		return
	}

	go proxyWorldToSubprocess(s.toSubprocess, conn)
	go proxySubprocessToWorld(conn, s.fromSubprocess)
}

// proxyUDP accepts connections on the given listener. For each one it dials the outside world
// and proxies data back and forth. It blocks until the listener returns an error, which only
// happens when the UDP stack shuts down.
// func proxyUDP(l *udpListener) error {
// 	for {
// 		conn, err := l.Accept()
// 		if err != nil {
// 			return fmt.Errorf("listener.Accept returned with error: %w", err)
// 		}

// 		// dial will take a while to complete; do not block on next accept
// 		go proxyUDPConn(conn)
// 	}
// }

// proxyUDPConn proxies data received on one UDP connection to the world, and back the other way.
func proxyUDPConn(s *stream) {
	conn, err := net.Dial("udp", s.world.String())
	if err != nil {
		log.Printf("service loop exited with error: %v", err)
		return
	}

	go proxyWorldToSubprocess(s.toSubprocess, conn)
	go proxySubprocessToWorld(conn, s.fromSubprocess)
}

// proxyWorldToSubprocess copies packets received from the world to the subprocess
func proxyWorldToSubprocess(toSubprocess io.Writer, fromWorld net.Conn) {
	buf := make([]byte, 1<<20)
	for {
		n, err := fromWorld.Read(buf)
		if err == io.EOF {
			// how to indicate to outside world that we're done?
			return
		}
		if err != nil {
			// how to indicate to outside world that the read failed?
			log.Printf("failed to read from world in proxy: %v, abandoning", err)
			return
		}

		// send packet to channel, drop on failure
		_, err = toSubprocess.Write(buf[:n])
		if err != nil {
			log.Printf("error writing data to subprocess: %v, dropping %d bytes", err, n)
		}
	}
}

// proxyWorldToSubprocess copies packets received from the subprocess to the world
func proxySubprocessToWorld(toWorld net.Conn, fromSubprocess chan []byte) {
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

		// start listening for TCP and proxy each one to the world
		go proxyTCP(tcpstack.Listen("*"))

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

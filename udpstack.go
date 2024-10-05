package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UDP stack

type udpStack struct {
	streamsBySrcDst map[string]*stream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet

	// packets to this dns server+port are intercepted and replied to directly
	dnsServer string
	dnsPort   layers.UDPPort

	listenerMu sync.Mutex
	listeners  []*udpListener
}

func newUDPStack(toSubprocess chan []byte) *udpStack {
	return &udpStack{
		streamsBySrcDst: make(map[string]*stream),
		toSubprocess:    toSubprocess,
		dnsServer:       "10.1.1.1",
		dnsPort:         layers.UDPPort(53),
	}
}

// notifyListeners is called when a new stream is created. It finds the first listener
// that will accept the given stream. It never blocks.
func (s *udpStack) notifyListeners(stream *stream) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	for _, listener := range s.listeners {
		if listener.pattern == "*" || listener.pattern == fmt.Sprintf(":%d", stream.world.Port) {
			listener.connections <- stream
			return
		}
	}

	log.Printf("nobody listening for udp to %v, dropping!", stream.world)
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
func (s *udpStack) Listen(pattern string) *udpListener {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	listener := udpListener{pattern: pattern, connections: make(chan *stream, 64)}
	s.listeners = append(s.listeners, &listener)
	return &listener
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

		s.streamsBySrcDst[srcdst] = stream

		s.notifyListeners(stream)
	}

	// forward the data to application-level listeners
	log.Printf("got %d udp bytes to %v:%v (%q), delivering to application",
		len(udp.Payload), ipv4.DstIP, udp.DstPort, preview(udp.Payload))

	stream.deliverToApplication(udp.Payload)
}

// udpListener is the interface for the application to intercept TCP connections
type udpListener struct {
	pattern     string
	connections chan *stream // the tcpStack sends streams here when they are created and they match the pattern above
}

// Accept accepts an intercepted connection. Later this will implement net.Listener.Accept
func (l *udpListener) Accept() (*stream, error) {
	stream := <-l.connections
	if stream == nil {
		// this means the channel is closed, which means the tcpStack was shut down
		return nil, net.ErrClosed
	}
	return stream, nil
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

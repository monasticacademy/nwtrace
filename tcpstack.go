package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCP stream

type TCPState int

const (
	StateInit TCPState = iota + 1
	StateSynchronizing
	StateConnected
	StateFinished
)

type tcpStream struct {
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

func newTCPStream(protool string, world AddrPort, subprocess AddrPort) *tcpStream {
	stream := tcpStream{
		protocol:       protool,
		world:          world,
		subprocess:     subprocess,
		state:          StateInit,
		fromSubprocess: make(chan []byte, 1024),
		serializeBuf:   gopacket.NewSerializeBuffer(),
	}

	return &stream
}

func (s *tcpStream) deliverToApplication(payload []byte) {
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

// TCP stack

type tcpStack struct {
	streamsBySrcDst map[string]*tcpStream
	toSubprocess    chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet

	listenerMu sync.Mutex
	listeners  []*tcpListener
}

func newTCPStack(toSubprocess chan []byte) *tcpStack {
	return &tcpStack{
		streamsBySrcDst: make(map[string]*tcpStream),
		toSubprocess:    toSubprocess,
	}
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

	listener := tcpListener{pattern: pattern, connections: make(chan *tcpStream, 64)}
	s.listeners = append(s.listeners, &listener)
	return &listener
}

// notifyListeners is called when a new stream is created. It finds the first listener
// that will accept the given stream. It never blocks.
func (s *tcpStack) notifyListeners(stream *tcpStream) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	for _, listener := range s.listeners {
		if listener.pattern == "*" || listener.pattern == fmt.Sprintf(":%d", stream.world.Port) {
			listener.connections <- stream
			return
		}
	}

	log.Printf("nobody listening for tcp to %v, dropping!", stream.world)
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
		stream = newTCPStream("tcp", dst, src)

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

		// update TCP sequence number -- this is not an increment but an overwrite, so no race condition here
		atomic.StoreUint32(&stream.ack, tcp.Seq+uint32(len(tcp.Payload)))

		// deliver the payload to application-level listeners
		stream.deliverToApplication(tcp.Payload)
	}
}

// tcpListener is the interface for the application to intercept TCP connections
type tcpListener struct {
	pattern     string
	connections chan *tcpStream // the tcpStack sends streams here when they are created and they match the pattern above
}

// Accept accepts an intercepted connection. Later this will implement net.Listener.Accept
func (l *tcpListener) Accept() (*tcpStream, error) {
	stream := <-l.connections
	if stream == nil {
		// this means the channel is closed, which means the tcpStack was shut down
		return nil, net.ErrClosed
	}
	return stream, nil
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
	stream    *tcpStream
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

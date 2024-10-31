package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UDP packet

type udpPacket struct {
	ipv4header *layers.IPv4
	udpheader  *layers.UDP
	payload    []byte
}

// udpHandlerFunc is a function that receives UDP packets. Each call to response.Write
// will write a UDP packet back to the subprocess that looks as if it comes from
// the destination to which the original packet was sent. No matter what you put in
// the source or destination address, the
type udpHandlerFunc func(w udpResponder, packet *udpPacket)

// udpMuxEntry is a pattern and corresponding handler, for use in the mux table for the udp stack
type udpMuxEntry struct {
	handler udpHandlerFunc
	pattern string
}

// UDP stack

type udpStack struct {
	toSubprocess chan []byte // data sent to this channel goes to subprocess as raw IPv4 packet
	buf          gopacket.SerializeBuffer

	handlerMu sync.Mutex
	handlers  []*udpMuxEntry
}

func newUDPStack(toSubprocess chan []byte) *udpStack {
	return &udpStack{
		toSubprocess: toSubprocess,
		buf:          gopacket.NewSerializeBuffer(),
	}
}

// notifyHandlers is called when a new packet arrives. It finds the first handler
// with a pattern that matches the packet and delivers the packet to it
func (s *udpStack) notifyHandlers(w udpResponder, packet *udpPacket) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()

	for _, entry := range s.handlers {
		if entry.pattern == "*" || entry.pattern == fmt.Sprintf(":%d", packet.udpheader.DstPort) {
			entry.handler(w, packet)
			return
		}
	}

	verbosef("nobody listening for udp to %v:%v, dropping!", packet.ipv4header.DstIP, packet.udpheader.DstPort)
}

// udpResponder is the interface for writing back UDP packets
type udpResponder interface {
	// write a UDP packet back to the subprocess
	Write(payload []byte) (n int, err error)

	// set the source IP in the header for UDP packets sent to Write()
	SetSourceIP(ip net.IP)

	// set the source port in the header for UDP packets sent to Write()
	SetSourcePort(port uint16)

	// set the destination IP in the header for UDP packets sent to Write()
	SetDestIP(ip net.IP)

	// set the destination port in the header for UDP packets sent to Write()
	SetDestPort(port uint16)
}

type udpStackResponder struct {
	stack      *udpStack
	udpheader  *layers.UDP
	ipv4header *layers.IPv4
}

func (r *udpStackResponder) SetSourceIP(ip net.IP) {
	r.ipv4header.SrcIP = ip
}

func (r *udpStackResponder) SetSourcePort(port uint16) {
	r.udpheader.SrcPort = layers.UDPPort(port)
}

func (r *udpStackResponder) SetDestIP(ip net.IP) {
	r.ipv4header.DstIP = ip
}

func (r *udpStackResponder) SetDestPort(port uint16) {
	r.udpheader.DstPort = layers.UDPPort(port)
}

func (r *udpStackResponder) Write(payload []byte) (int, error) {
	// set checksums and lengths
	r.udpheader.SetNetworkLayerForChecksum(r.ipv4header)

	// log
	verbosef("sending udp packet to subprocess: %s", summarizeUDP(r.ipv4header, r.udpheader, payload))

	// serialize the data
	packet, err := serializeUDP(r.ipv4header, r.udpheader, payload, r.stack.buf)
	if err != nil {
		return 0, fmt.Errorf("error serializing UDP packet: %w", err)
	}

	// make a copy because the same buffer will be re-used
	cp := make([]byte, len(packet))
	copy(cp, packet)

	// send to the subprocess channel non-blocking
	select {
	case r.stack.toSubprocess <- cp:
	default:
		return 0, fmt.Errorf("channel for sending udp to subprocess would have blocked")
	}

	// return number of bytes passed in, not number of bytes sent to output
	return len(payload), nil
}

// HandleFunc registers a handler for UDP packets according to destination IP and/or por
//
// Pattern can a hostname, a port, a hostname:port, or "*" for everything". Ports are prepended
// with colons. Valid patterns are:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
//
// Later this will be like net.Listen
func (s *udpStack) HandleFunc(pattern string, handler udpHandlerFunc) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()

	s.handlers = append(s.handlers, &udpMuxEntry{pattern: pattern, handler: handler})
}

func (s *udpStack) handlePacket(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) {
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

	w := udpStackResponder{
		stack:      s,
		udpheader:  &replyudp,
		ipv4header: &replyipv4,
	}

	// forward the data to application-level listeners
	verbosef("got %d udp bytes to %v:%v, delivering to application", len(udp.Payload), ipv4.DstIP, udp.DstPort)

	s.notifyHandlers(&w, &udpPacket{ipv4, udp, payload})
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
		errorf("error serializing IP part of packet: %v", err)
	}

	return tmp.Bytes(), nil
}

// summarizeUDP summarizes a UDP packet into a single line for logging
func summarizeUDP(ipv4 *layers.IPv4, udp *layers.UDP, payload []byte) string {
	return fmt.Sprintf("UDP %v:%d => %v:%d - Len %d",
		ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort, len(udp.Payload))
}

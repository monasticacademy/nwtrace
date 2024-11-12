package main

import (
	"fmt"

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
	app          *mux
}

func newUDPStack(app *mux, link chan []byte) *udpStack {
	return &udpStack{
		toSubprocess: link,
		buf:          gopacket.NewSerializeBuffer(),
		app:          app,
	}
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

	s.app.notifyUDP(&w, &udpPacket{ipv4, udp, payload})
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

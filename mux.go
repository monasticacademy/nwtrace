package main

import (
	"net"
	"strings"
	"sync"
)

// match a listen pattern to an address string of the form HOST:PORT
func patternMatches(pattern string, addr net.Addr) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, ":") && strings.HasSuffix(addr.String(), pattern) {
		return true
	}
	return false
}

// mux dispatches network connections to listeners according to patterns
type mux struct {
	mu          sync.Mutex
	tcpHandlers []*tcpListener
	udpHandlers []*udpMuxEntry
}

// tcpHandlerFunc is a function that receives TCP connections
type tcpHandlerFunc func(conn net.Conn)

// udpHandlerFunc is a function that receives UDP packets. Each call to w.Write
// will send a UDP packet back to the subprocess that looks as if it comes from
// the destination to which the original packet was sent. No matter what you put in
// the source or destination address, the
type udpHandlerFunc func(w udpResponder, packet *udpPacket)

// udpMuxEntry is a pattern and corresponding handler, for use in the mux table for the udp stack
type udpMuxEntry struct {
	handler udpHandlerFunc
	pattern string
}

// ListenTCP returns a net.Listener that intercepts connections according to a filter pattern.
//
// Pattern can a hostname, a :port, a hostname:port, or "*" for everything". For example:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
//
// Later this will be like net.ListenTCP
func (s *mux) ListenTCP(pattern string) net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()

	listener := tcpListener{pattern: pattern, connections: make(chan net.Conn, 64)}
	s.tcpHandlers = append(s.tcpHandlers, &listener)
	return &listener
}

// HandleTCP calls the handler each time a new connection is intercepted mattching the
// given filter pattern.
//
// Pattern can a hostname, a :port, a hostname:port, or "*" for everything". For example:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
func (s *mux) HandleTCP(pattern string, handler tcpHandlerFunc) {
	l := s.ListenTCP(pattern)
	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				verbosef("accept returned errror: %v, exiting HandleFunc(%v)", err, pattern)
				return
			}

			go handler(conn)
		}
	}()
}

// HandleUDP registers a handler for UDP packets according to destination IP and/or por
//
// Pattern can a hostname, a port, a hostname:port, or "*" for everything". Ports are prepended
// with colons. Valid patterns are:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
//
// Later this will be like net.Listen
func (s *mux) HandleUDP(pattern string, handler udpHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.udpHandlers = append(s.udpHandlers, &udpMuxEntry{pattern: pattern, handler: handler})
}

// notifyListeners is called when a new stream is created. It finds the first listener
// that will accept the given stream. It never blocks.
func (s *mux) notifyTCP(stream net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, listener := range s.tcpHandlers {
		if patternMatches(listener.pattern, stream.LocalAddr()) {
			listener.connections <- stream
			return
		}
	}

	verbosef("nobody listening for tcp to %v, dropping", stream.LocalAddr())
}

// notifyUDP is called when a new packet arrives. It finds the first handler
// with a pattern that matches the packet and delivers the packet to it
func (s *mux) notifyUDP(w udpResponder, packet *udpPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.udpHandlers {
		if patternMatches(entry.pattern, packet.dst) {
			go entry.handler(w, packet)
			return
		}
	}

	verbosef("nobody listening for udp to %v, dropping!", packet.dst)
}

// udpResponder is the interface for writing back UDP packets
type udpResponder interface {
	// write a UDP packet back to the subprocess
	Write(payload []byte) (n int, err error)
}

// tcpListener implements net.Listener for connections dispatched by a mux
type tcpListener struct {
	pattern     string
	connections chan net.Conn // the tcpStack sends streams here when they are created and they match the pattern above
}

// Accept accepts an intercepted connection. Later this will implement net.Listener.Accept
func (l *tcpListener) Accept() (net.Conn, error) {
	stream := <-l.connections
	if stream == nil {
		// this means the channel is closed, which means the tcpStack was shut down
		return nil, net.ErrClosed
	}
	return stream, nil
}

// for net.Listener interface
func (l *tcpListener) Close() error {
	// TODO: unregister from the stack, then close(l.connections)
	verbose("tcpListener.Close() not implemented, ignoring")
	return nil
}

// for net.Listener interface, returns our side of the connection
func (l *tcpListener) Addr() net.Addr {
	verbose("tcpListener.Addr() was called, returning bogus address 0.0.0.0:0")
	// in truth we do not have a real address -- we listen for anything going anywhere
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

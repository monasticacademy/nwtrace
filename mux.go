package main

import (
	"net"
	"strings"
	"sync"
)

// tcpMux dispatches TCP connections to listeners according to patterns
type tcpMux struct {
	listenerMu sync.Mutex
	listeners  []*tcpListener
}

// Listen returns a net.Listener that intercepts connections according to a filter pattern.
//
// Pattern can a hostname, a :port, a hostname:port, or "*" for everything". For example:
//   - "example.com"
//   - "example.com:80"
//   - ":80"
//   - "*"
//
// Later this will be like net.Listen
func (s *tcpMux) Listen(pattern string) net.Listener {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	listener := tcpListener{pattern: pattern, connections: make(chan net.Conn, 64)}
	s.listeners = append(s.listeners, &listener)
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
func (s *tcpMux) HandleTCP(pattern string, handler tcpHandlerFunc) {
	l := s.Listen(pattern)
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

type tcpHandlerFunc func(conn net.Conn)

// match a listen pattern to an address string of the form HOST:PORT
func patternMatches(pattern, hostport string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, ":") && strings.HasSuffix(hostport, pattern) {
		return true
	}
	return false
}

// notifyListeners is called when a new stream is created. It finds the first listener
// that will accept the given stream. It never blocks.
func (s *tcpMux) notifyListeners(stream net.Conn) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()

	for _, listener := range s.listeners {
		if patternMatches(listener.pattern, stream.LocalAddr().String()) {
			listener.connections <- stream
			return
		}
	}

	verbosef("nobody listening for tcp to %v, dropping", stream.LocalAddr())
}

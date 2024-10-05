package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

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
func proxyUDP(l *udpListener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("listener.Accept returned with error: %w", err)
		}

		// dial will take a while to complete; do not block on next accept
		go proxyUDPConn(conn)
	}
}

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

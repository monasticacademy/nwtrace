package main

import (
	"io"
	"net"
)

// proxyTCP proxies data received on one TCP connection to the world, and back the other way.
func proxyTCP(subprocess net.Conn) {
	// the connections's "LocalAddr" is actually the place the other side (the subprocess) was trying
	// to reach, so that's the address we dial in order to proxy
	world, err := net.Dial("tcp", subprocess.LocalAddr().String())
	if err != nil {
		verbosef("service loop exited with error: %v", err)
		return
	}

	go proxyWorldToSubprocess(subprocess, world)
	go proxySubprocessToWorld(world, subprocess)
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
			errorf("error reading from world in proxy: %v, abandoning", err)
			return
		}

		// send packet to channel, drop on failure
		_, err = toSubprocess.Write(buf[:n])
		if err != nil {
			errorf("error writing data to subprocess: %v, dropping %d bytes", err, n)
		}
	}
}

// proxyWorldToSubprocess copies packets received from the subprocess to the world
func proxySubprocessToWorld(toWorld net.Conn, fromSubprocess io.Reader) {
	buf := make([]byte, 1<<20)
	for {
		n, err := fromSubprocess.Read(buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			errorf("error reading from subprocess in proxy: %v, abandoning", err)
			return
		}

		verbosef("proxying %d bytes from subprocess to world", n)
		_, err = toWorld.Write(buf[:n])
		if err != nil {
			// how to indicate to outside world that the write failed?
			errorf("error writing %d bytes from subprocess to world: %v", n, err)
			return
		}
	}
}

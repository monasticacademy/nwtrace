package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var tap = flag.Bool("tap", false, "use tap instead of tun")
var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")

type endpointWriter struct {
	ep tcpip.Endpoint
}

type tcpipError struct {
	inner tcpip.Error
}

func (e *tcpipError) Error() string {
	return e.inner.String()
}

func (e *endpointWriter) Write(p []byte) (int, error) {
	var r bytes.Reader
	r.Reset(p)
	n, err := e.ep.Write(&r, tcpip.WriteOptions{})
	if err != nil {
		return int(n), &tcpipError{
			inner: err,
		}
	}
	if n != int64(len(p)) {
		return int(n), io.ErrShortWrite
	}
	return int(n), nil
}

func echo(wq *waiter.Queue, ep tcpip.Endpoint) {
	defer ep.Close()

	// Create wait queue entry that notifies a channel.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	w := endpointWriter{
		ep: ep,
	}

	for {
		var buf bytes.Buffer
		if _, err := ep.Read(&buf, tcpip.ReadOptions{}); err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}

			return
		}

		log.Printf("echoing %q", buf.String())

		if _, err := w.Write(buf.Bytes()); err != nil {
			return
		}
	}
}

func Main() error {
	var args struct {
		Tun     string
		Address string
		Port    uint16
	}
	arg.MustParse(&args)

	// lock the OS thread in order to switch network namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// save a reference to our initial network namespace so we can get back
	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("error getting initial network namespace: %w", err)
	}
	defer origns.Close()

	// parse the mac address
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// parse our IP address
	localAddr := net.ParseIP(args.Address)
	if localAddr == nil {
		log.Fatalf("Bad IP address: %v", args.Address)
	}

	var addrWithPrefix tcpip.AddressWithPrefix
	var proto tcpip.NetworkProtocolNumber
	if localAddr.To4() != nil {
		addrWithPrefix = tcpip.AddrFromSlice(localAddr.To4()).WithPrefix()
		proto = ipv4.ProtocolNumber
	} else if localAddr.To16() != nil {
		addrWithPrefix = tcpip.AddrFromSlice(localAddr.To16()).WithPrefix()
		proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown IP type: %v", args.Address)
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// Create a new network namespace
	newns, err := netns.New()
	if err != nil {
		return fmt.Errorf("error creating network namespace: %w", err)
	}
	defer newns.Close()

	// create a new tun device in the new namespace
	fd, err := tun.Open(args.Tun)
	if err != nil {
		return fmt.Errorf("error creating tun device: %w", err)
	}

	// find the link for it
	link, err := netlink.LinkByName(args.Tun)
	if err != nil {
		return fmt.Errorf("error finding link for new tun device %q: %w", args.Tun, err)
	}

	// bring the link up
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error bringing up link for %q: %w", args.Tun, err)
	}

	// assign a local address and subnet to the link
	linksubnet, err := netlink.ParseIPNet("10.1.2.255/24")
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

	// parse the global subnet 0.0.0.0/0
	globalsubnet, err := netlink.ParseIPNet("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("error parsing global subnet: %w", err)
	}

	// add a route that sends all traffic going anywhere to our local address
	err = netlink.RouteAdd(&netlink.Route{
		Dst: globalsubnet,
		Gw:  localAddr,
	})
	if err != nil {
		return fmt.Errorf("error creating default route: %w", err)
	}

	// launch a subprocess in the namespace
	cmd := exec.Command("/bin/sh")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = []string{"PS1=CONTAINER # "}

	// no need for CLONE_NEWNET here because we already switched into the new namespace
	// cmd.SysProcAttr = &syscall.SysProcAttr{
	// 	Cloneflags: syscall.CLONE_NEWNET,
	// }

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	go func() {
		_ = cmd.Wait()
		exitCode := cmd.ProcessState.ExitCode()
		log.Printf("subprocess exited with code %d, shutting down httptap", exitCode)
		os.Exit(exitCode)
	}()

	//

	// set up software network stack
	mtu, err := rawfile.GetMTU(args.Tun)
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: *tap,
		Address:        tcpip.LinkAddress(maddr),
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.CreateNIC(1, linkEP); err != nil {
		log.Fatal(err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: addrWithPrefix,
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		log.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr, err)
	}

	global := strings.Repeat("\x00", addrWithPrefix.Address.Len())
	subnet, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice([]byte(global)),
		tcpip.MaskFrom(global))
	if err != nil {
		log.Fatal(err)
	}

	// set up a route table that routes everything to us
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	var wq waiter.Queue

	// create TCP endpoint, bind it, then start listening
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	//ep, e := s.NewRawEndpoint(tcp.ProtocolNumber, header.IPv4ProtocolNumber, &wq, true)
	if e != nil {
		return fmt.Errorf("error creating a raw endpoint: %w", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: args.Port}); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}

	// Wait for connections to appear.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	log.Printf("listening for connections on %v...", args.Tun)
	for {
		n, wq, err := ep.Accept(nil)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}

			log.Fatal("Accept() failed:", err)
		}

		log.Println("accepted a connection...")

		go echo(wq, n) // S/R-SAFE: sample code.
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

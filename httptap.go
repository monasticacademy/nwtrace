package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/alexflint/go-arg"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func Main() error {
	var args struct {
		Tun     string   `default:"httptap"`
		Link    string   `default:"10.1.1.255/24"`
		Route   string   `default:"0.0.0.0/0"`
		Gateway string   `default:"10.1.1.1"`
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	// lock the OS thread in order to switch network namespaces (network namespaces are thread-specific)
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
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: args.Tun,
		},
	}

	tun, err := water.New(config)
	if err != nil {
		log.Fatal(err)
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

	// launch a subprocess -- we are already in the namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command[1:]
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PS1=HTTPTAP # "}
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// start a goroutine to process packets from the subprocess -- this will be killed
	// when the subprocess completes
	log.Printf("listening on %v", args.Tun)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				log.Fatal(err)
			}
			buf := buf[:n]
			log.Printf("read a packet of size %d", len(buf))
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

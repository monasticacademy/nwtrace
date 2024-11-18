package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

func Main() error {
	var args struct {
		Interface string `arg:"positional,required"`
		Remote    string `arg:"positional,required"`
		Count     int    `default:"2"`
	}
	arg.MustParse(&args)

	// packetsource, err := afpacket.NewTPacket(afpacket.OptInterface(args.Interface))
	// if err != nil {
	// 	return nil
	// }

	iface, err := net.InterfaceByName(args.Interface)
	if err != nil {
		return err
	}

	// packet.Raw means listen for raw IP packets (requires root permissions)
	// unix.ETH_P_ALL means listen for all packets
	conn, err := packet.Listen(iface, packet.Raw, unix.ETH_P_ALL, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("you need root permissions to read raw packets (%w)", err)
		}
		return fmt.Errorf("error listening for raw packet: %w", err)
	}

	// set promiscuous mode so that we see everything
	err = conn.SetPromiscuous(true)
	if err != nil {
		return fmt.Errorf("error setting raw packet connection to promiscuous mode: %w", err)
	}

	// write a udp packet
	udpconn, err := net.Dial("udp", args.Remote)
	if err != nil {
		return fmt.Errorf("error dialing %v: %w", args.Remote, err)
	}
	udpconn.Write([]byte("hello from udp-experiment..."))

	// read a packet
	buf := make([]byte, iface.MTU)
	for i := 0; i < args.Count; i++ {
		n, srcmac, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("error reading raw packet: %w", err)
		}
		_ = srcmac

		// decode with gopacket
		log.Printf("read %d bytes", n)
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
		log.Println(packet.Dump())
	}

	return nil
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

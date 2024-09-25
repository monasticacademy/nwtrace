package main

import (
	"log"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

func Main() error {
	var args struct {
		Device string `default:"httptap"`
	}
	arg.MustParse(&args)

	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: args.Device,
		},
	}

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}
	var frame ethernet.Frame

	log.Printf("listening on new device %q...", args.Device)

	for {
		frame.Resize(1500)
		n, err := ifce.Read([]byte(frame))
		if err != nil {
			log.Fatal(err)
		}
		frame = frame[:n]
		log.Printf("Dst: %s\n", frame.Destination())
		log.Printf("Src: %s\n", frame.Source())
		log.Printf("Ethertype: % x\n", frame.Ethertype())
		log.Printf("Payload: % x\n", frame.Payload())
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

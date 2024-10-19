package main

import (
	"log"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/r3labs/sse"
)

func Main() error {
	var args struct {
		URL string `arg:"positional,required"`
	}
	arg.MustParse(&args)

	client := sse.NewClient(args.URL)
	return client.Subscribe("messages", func(msg *sse.Event) {
		// Got some data!
		log.Println("received data: ", string(msg.Data))
	})
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

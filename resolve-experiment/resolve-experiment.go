package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/alexflint/go-arg"
)

func Main() error {
	var args struct {
		Host string `arg:"positional,required"`
	}
	arg.MustParse(&args)

	ctx := context.Background()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", args.Host)
	if err != nil {
		return fmt.Errorf("the default resolver said: %w", err)
	}
	log.Println(ips)
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

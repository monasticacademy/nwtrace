package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/alexflint/go-arg"
)

// this is a TCP server that writes a fixed string and then closes the connection, in order to investigate the
// behavior of netcat with respect to FIN packets

func Main() error {
	var args struct {
		Addr string `arg:"positional" default:":11223"`
	}
	arg.MustParse(&args)

	log.Printf("listening on %v ...", args.Addr)
	l, err := net.Listen("tcp", args.Addr)
	if err != nil {
		return fmt.Errorf("error listening on %v: %w", args.Addr, err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		fmt.Fprintln(conn, "hello fin experiment")
		conn.Close()
		log.Printf("accepted and closed a connection from %v", conn.RemoteAddr())
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

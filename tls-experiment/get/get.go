package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/alexflint/go-arg"
)

func Main() error {
	var args struct {
		Addr string `arg:"positional,required"`
		Name string `arg:"positional,required"`
	}
	arg.MustParse(&args)

	// dial the server
	conn, err := net.Dial("tcp", args.Addr)
	if err != nil {
		return fmt.Errorf("error dialing server: %w", err)
	}

	tlsconn := tls.Client(conn, &tls.Config{ServerName: args.Name})

	err = tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("tls handshake failed: %w", err)
	}

	err = tlsconn.VerifyHostname(args.Name)
	if err != nil {
		return fmt.Errorf("tls hostname not verified: %w", err)
	}

	log.Println("success")

	// req, err := http.NewRequest("GET", args.URL, nil)
	// if err != nil {
	// 	return err
	// }

	// var client http.Client
	// client.Transport = &pinnedTransport{args.Server}

	// net.DefaultResolver

	// resp, err := http.Get(args.URL)
	// if err != nil {
	// 	return err
	// }
	// defer resp.Body.Close()

	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return err
	// }
	// log.Println(string(body))

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

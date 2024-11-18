package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
)

func Main() error {
	var args struct {
		Addr     string `arg:"positional,required"`
		Hostname string `arg:"positional,required"`
	}
	arg.MustParse(&args)

	// dial the server
	conn, err := net.Dial("tcp", args.Addr)
	if err != nil {
		return fmt.Errorf("error dialing server: %w", err)
	}

	tlsconn := tls.Client(conn, &tls.Config{ServerName: args.Hostname})

	err = tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("tls handshake failed: %w", err)
	}

	err = tlsconn.VerifyHostname(args.Hostname)
	if err != nil {
		return fmt.Errorf("tls hostname not verified: %w", err)
	}

	// create http request
	req, err := http.NewRequest("GET", "https://"+args.Hostname, nil)
	if err != nil {
		return err
	}

	// write the request to the TLS connection
	err = req.Write(tlsconn)
	if err != nil {
		return fmt.Errorf("error sending http request over tls: %w", err)
	}

	// read the response from the TLS connection
	resp, err := http.ReadResponse(bufio.NewReader(tlsconn), req)
	if err != nil {
		return fmt.Errorf("error reading http response over tls: %w", err)
	}
	defer resp.Body.Close()

	// read the whole body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading http body over tls: %w", err)
	}

	// log the result
	log.Println(strings.TrimSpace(string(body)))

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

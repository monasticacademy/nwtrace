package main

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/joemiller/certin"
)

func writeCertFile(cert []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error opening pem file for writing: %w", err)
	}
	defer f.Close()

	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return fmt.Errorf("error encoding CA to pem: %w", err)
	}

	log.Printf("created %v", path)
	return nil
}

func Main() error {
	var args struct {
		Port string `default:":19870"`
	}
	arg.MustParse(&args)

	root, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true})
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}

	// leaf, err := certin.NewCert(root, certin.Request{
	// 	CN:   "example.com",
	// 	SANs: []string{"example.com", "www.example.com", "127.0.0.1"},
	// })
	// if err != nil {
	// 	return fmt.Errorf("error creating leaf certificate: %w", err)
	// }

	// write the certificate authority to a temporary file
	err = writeCertFile(root.Certificate.Raw, "ca.crt")
	if err != nil {
		return err
	}

	// write the server certificate to a temporary file
	// err = writeCertFile(leaf.Certificate.Raw, "certificate.crt")
	// if err != nil {
	// 	return err
	// }

	// start an HTTP server
	const plaintext = "hello httptap world"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, plaintext)
	}))
	server.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("got challenge for %q", hello.ServerName)
			onthefly, err := certin.NewCert(root, certin.Request{CN: hello.ServerName})
			if err != nil {
				log.Println("error creating cert: %w", err)
				return nil, fmt.Errorf("error creating on-the-fly certificate for %q: %w", hello.ServerName, err)
			}

			err = writeCertFile(onthefly.Certificate.Raw, "certificate.crt")
			if err != nil {
				log.Printf("error writing on-the-fly certificate to file: %v, ignoring", err)
			}

			tlscert := onthefly.TLSCertificate()
			return &tlscert, nil
		},
	}
	server.Listener, err = net.Listen("tcp", args.Port)
	if err != nil {
		return fmt.Errorf("unable to listen on %v: %w", args.Port, err)
	}

	server.StartTLS()
	defer server.Close()

	// communicate with the server using an http.Client configured to trust our CA
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    root.CertPool(),
			ServerName: "example.com",
		},
	}
	http := http.Client{
		Transport: transport,
	}

	url := fmt.Sprintf("https://127.0.0.1%v/", args.Port)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	// verify the response
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body != plaintext {
		return fmt.Errorf("mismatch, got: %q", body)
	}

	log.Printf("verified connection works locally, now listening at %v ...", server.URL)
	select {}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

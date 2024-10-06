package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/joemiller/certin"
)

func proxyHTTPS(l net.Listener, root *certin.KeyAndCert) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept returned errror: %v, exiting proxyHTTPS", err)
			return
		}

		log.Printf("intercepted a connection to %v", conn.LocalAddr())

		go func() {
			var challenge string

			// create a tls server with certificates generated on-the-fly from our root CA
			tlsconn := tls.Server(conn, &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					log.Printf("got challenge for %q", hello.ServerName)
					challenge = hello.ServerName

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
			})

			log.Printf("reading request sent to %v ...", conn.LocalAddr())

			// read the HTTP request
			req, err := http.ReadRequest(bufio.NewReader(tlsconn))
			if err != nil {
				log.Printf("error reading http request over tls server conn: %v, aborting", err)
				return
			}
			defer req.Body.Close()

			// read the HTTP body
			// body, err := io.ReadAll(req.Body)
			// if err != nil {
			// 	log.Printf("error reading http request body over tls server conn: %v, aborting", err)
			// 	return
			// }

			respbody := fmt.Sprintf("hello from httptap[%v]", challenge)

			resp := http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				ContentLength: int64(len(respbody)),
				Body:          io.NopCloser(bytes.NewReader([]byte(respbody))),
			}

			err = resp.Write(tlsconn)
			if err != nil {
				log.Printf("error writing response to tls server conn: %v", err)
				return
			}

			log.Printf("intercepted %v %v, replyied with 200", req.Method, req.URL)

			//tlsconn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello from httptap\r\n\r\n"))
		}()
	}
}

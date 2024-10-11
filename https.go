package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/fatih/color"
	"github.com/joemiller/certin"
)

func proxyHTTPS(l net.Listener, root *certin.KeyAndCert) {
	for {
		conn, err := l.Accept()
		if err != nil {
			verbosef("accept returned errror: %v, exiting proxyHTTPS", err)
			return
		}

		verbosef("intercepted a connection to %v", conn.LocalAddr())

		go func() {
			var serverName string

			// create a tls server with certificates generated on-the-fly from our root CA
			tlsconn := tls.Server(conn, &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					verbosef("got challenge for %q", hello.ServerName)
					serverName = hello.ServerName

					onthefly, err := certin.NewCert(root, certin.Request{CN: hello.ServerName})
					if err != nil {
						errorf("error creating cert: %v", err)
						return nil, fmt.Errorf("error creating on-the-fly certificate for %q: %w", hello.ServerName, err)
					}

					err = writeCertFile(onthefly.Certificate.Raw, "certificate.crt")
					if err != nil {
						errorf("error writing on-the-fly certificate to file: %v, ignoring", err)
					}

					tlscert := onthefly.TLSCertificate()
					return &tlscert, nil
				},
			})

			verbosef("reading request sent to %v ...", conn.LocalAddr())

			// read the HTTP request
			req, err := http.ReadRequest(bufio.NewReader(tlsconn))
			if err != nil {
				errorf("error reading http request over tls server conn: %v, aborting", err)
				return
			}
			defer req.Body.Close()

			reqcolor := color.New(color.FgBlue, color.Bold)
			reqcolor.Printf("---> %v %v\n", req.Method, req.URL)

			// do roundtrip to the actual server in the world -- we use RoundTrip here because
			// we do not want to follow redirects or accumulate our own cookies
			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				// error here means the server could not be resolved or a TCP connection could not be made,
				// or TLS could not be negotiated, or something like that
				body := []byte(err.Error())
				resp = &http.Response{
					Status:        http.StatusText(http.StatusBadGateway),
					StatusCode:    http.StatusBadGateway,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					ContentLength: int64(len(body)),
					Body:          io.NopCloser(bytes.NewReader(body)),
				}

				errorf("error proxying request to world: %v, returning %v", err, resp.Status)
			}

			var respcolor *color.Color
			switch {
			case resp.StatusCode < 300:
				respcolor = color.New(color.FgGreen)
			case resp.StatusCode < 400:
				respcolor = color.New(color.FgMagenta)
			case resp.StatusCode < 500:
				respcolor = color.New(color.FgYellow)
			default:
				respcolor = color.New(color.FgRed)
			}
			respcolor.Printf("<--- %v %v\n", resp.StatusCode, req.URL)

			resp.Header.Set("x-httptap", serverName)

			// proxy the response from the world back to the subprocess
			err = resp.Write(tlsconn)
			if err != nil {
				errorf("error writing response to tls server conn: %v", err)
				return
			}

			verbosef("intercepted %v %v, replyied with %v", req.Method, req.URL, resp.Status)
		}()
	}
}

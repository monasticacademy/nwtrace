package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/joemiller/certin"
)

// HTTPCall models the information about an HTTP request/response that is exposed over the API and serialized to disk
type HTTPCall struct {
	Request  HTTPRequest  `json:"request"`
	Response HTTPResponse `json:"response"`
}

// HTTPRequest models the information about an HTTP request that is exposed over the API and serialized to disk
type HTTPRequest struct {
	Method string
	URL    string
}

// HTTPResponse models the information about an HTTP request that is exposed over the API and serialized to disk
type HTTPResponse struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Length     int64  `json:"length"`
}

// httpListener receives HTTPCalls each time a request/response is completed
type httpListener chan *HTTPCall

// the listeners waiting for HTTPCalls
var httpListeners []httpListener

// the complete set of HTTP calls up to the present moment
var httpCalls []*HTTPCall

// the mutex that protects the above slcies
var httpMu sync.Mutex

// add a listener that will receive events for each next HTTP call; the set of historical
// HTTP calls is returned in a way that guarantees none are missed
func listenHTTP() (httpListener, []*HTTPCall) {
	httpMu.Lock()
	defer httpMu.Unlock()

	l := make(httpListener, 128)
	httpListeners = append(httpListeners, l)
	return l, httpCalls
}

// add an HTTP call and notify listeners
func notifyHTTP(call *HTTPCall) {
	httpMu.Lock()
	defer httpMu.Unlock()

	httpCalls = append(httpCalls, call)
	for _, l := range httpListeners {
		l <- call // TODO: make non-block if necessary
	}
}

// close all HTTP listeners so that the receiving end can exit
func finishHTTP() {
	httpMu.Lock()
	defer httpMu.Unlock()

	for _, l := range httpListeners {
		close(l)
	}
}

// listen for incomming connections on l and proxy each one to the outside world, while sending
// information about the request/response pairs to all HTTP listeners
func proxyHTTPS(l net.Listener, root *certin.KeyAndCert) {
	for {
		conn, err := l.Accept()
		if err != nil {
			verbosef("accept returned errror: %v, exiting proxyHTTPS", err)
			return
		}

		verbosef("intercepted a connection to %v", conn.LocalAddr())

		go func() {
			defer handlePanic()

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

			// the request may contain a relative URL but we need an absolute URL for RoundTrip to know
			// where to dial
			if req.URL.Host == "" {
				req.URL.Host = req.Host
				if req.URL.Host == "" {
					req.URL.Host = conn.LocalAddr().String()
				}
			}
			if req.URL.Scheme == "" {
				req.URL.Scheme = "https"
			}

			// create a RoundTripper that always dials the IP we intercepted packets to
			dialTo := req.URL.Host
			if !strings.Contains(dialTo, ":") {
				dialTo += ":https"
			}

			// these parameters copied from http.DefaultTransport
			roundTripper := http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" {
						return nil, fmt.Errorf("network %q was requested of dialer pinned to tcp (%v)", network, dialTo)
					}
					verbosef("pinned dialer ignoring %q and dialing %v", address, dialTo)
					return net.Dial("tcp", dialTo)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          5,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}

			// do roundtrip to the actual server in the world -- we use RoundTrip here because
			// we do not want to follow redirects or accumulate our own cookies
			resp, err := roundTripper.RoundTrip(req)
			if err != nil {
				// error here means the server hostname could not be resolved, or a TCP connection could not be made,
				// or TLS could not be negotiated, or something like that
				body := []byte(err.Error())
				resp = &http.Response{
					Proto:         req.Proto,
					ProtoMajor:    req.ProtoMajor,
					ProtoMinor:    req.ProtoMinor,
					Status:        http.StatusText(http.StatusBadGateway),
					StatusCode:    http.StatusBadGateway,
					Header:        make(http.Header),
					ContentLength: int64(len(body)),
					Body:          io.NopCloser(bytes.NewReader(body)),
				}

				errorf("error proxying request to %v: %v, returning %v", dialTo, err, resp.Status)
			}

			// make the summary the we will log to disk and expose via the API
			call := HTTPCall{
				Request: HTTPRequest{
					Method: req.Method,
					URL:    req.URL.String(),
				},
				Response: HTTPResponse{
					Status:     resp.Status,
					StatusCode: resp.StatusCode,
					Length:     resp.ContentLength,
				},
			}

			log.Println("notifyHTTP...")
			notifyHTTP(&call)

			// log the response
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

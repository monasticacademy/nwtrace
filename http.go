package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
	Request    HTTPRequest  `json:"request"`
	Response   HTTPResponse `json:"response"`
	TotalBytes int64        `json:"total_bytes"`
}

// HTTPRequest models the information about an HTTP request that is exposed over the API and serialized to disk
type HTTPRequest struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Host        string `json:"host"`
	ContentType string `json:"content_type"`
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

// TeeReadCloser returns a Reader that writes to w what it reads from r,
// just like io.TeeReader, and also implements Close
func TeeReadCloser(r io.ReadCloser, w io.Writer) io.ReadCloser {
	return &teeReadCloser{r, w}
}

type teeReadCloser struct {
	r io.ReadCloser
	w io.Writer
}

func (t *teeReadCloser) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}

func (t *teeReadCloser) Close() error {
	return t.r.Close()
}

// CountBytesConn is a net.Conn that counts bytes read and written
type countBytesConn struct {
	net.Conn
	read, written int64
}

func (conn *countBytesConn) Read(b []byte) (int, error) {
	n, err := conn.Conn.Read(b)
	conn.read += int64(n)
	return n, err
}

func (conn *countBytesConn) Write(b []byte) (int, error) {
	n, err := conn.Conn.Write(b)
	conn.written += int64(n)
	return n, err
}

// listen for incomming connections on l and proxy each one to the outside world, while sending
// information about the request/response pairs to all HTTP listeners
func proxyHTTPS(conn net.Conn, root *certin.KeyAndCert) {
	defer handlePanic()
	defer conn.Close()

	verbosef("intercepted a connection to %v", conn.LocalAddr())

	// wrap the connection with a byte counter
	counts := countBytesConn{Conn: conn}
	conn = &counts

	// create a tls server with certificates generated on-the-fly from our root CA
	var serverName string
	tlsconn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			verbosef("got challenge for %q", hello.ServerName)
			serverName = hello.ServerName

			onthefly, err := certin.NewCert(root, certin.Request{CN: hello.ServerName})
			if err != nil {
				errorf("error creating cert: %v", err)
				return nil, fmt.Errorf("error creating on-the-fly certificate for %q: %w", hello.ServerName, err)
			}

			tlscert := onthefly.TLSCertificate()
			return &tlscert, nil
		},
	})
	defer tlsconn.Close()

	verbosef("reading request sent to %v (%v) ...", conn.LocalAddr(), serverName)

	proxyHTTP(tlsconn)
}

// listen for incomming connections on l and proxy each one to the outside world, while sending
// information about the request/response pairs to all HTTP listeners
func proxyHTTP(conn net.Conn) {
	defer handlePanic()
	defer conn.Close()

	verbosef("intercepted a connection to %v", conn.LocalAddr())

	// wrap the connection with a byte counter
	counts := countBytesConn{Conn: conn}
	conn = &counts

	verbosef("reading request sent to %v ...", conn.LocalAddr())

	// read the HTTP request (TODO: support HTTP/2 using golang.org/x/net/http2)
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		errorf("error reading http request over tls server conn: %v, aborting", err)
		return
	}
	defer req.Body.Close()

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

	// capture the request body into memory for inspection later
	var reqbody bytes.Buffer
	req.Body = TeeReadCloser(req.Body, &reqbody)

	// do roundtrip to the actual server in the world -- we use RoundTrip here because
	// we do not want to follow redirects or accumulate our own cookies
	resp, err := roundTripper.RoundTrip(req)
	if err != nil {
		// error here means the server hostname could not be resolved, or a TCP connection could not be made,
		// or TLS could not be negotiated, or something like that
		errbody := []byte(err.Error())
		resp = &http.Response{
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Status:        http.StatusText(http.StatusBadGateway),
			StatusCode:    http.StatusBadGateway,
			Header:        make(http.Header),
			ContentLength: int64(len(errbody)),
			Body:          io.NopCloser(bytes.NewReader(errbody)),
		}

		errorf("error proxying request to %v: %v, returning %v", dialTo, err, resp.Status)
	}
	defer resp.Body.Close()

	resp.Header.Set("x-httptap", req.Host)

	// capture the response body into memory for later inspection
	var respbody bytes.Buffer
	resp.Body = TeeReadCloser(resp.Body, &respbody)

	// we are currently limited to talking HTTP/1.1 with the subprocess, even if the request we made
	// to the world was done in HTTP/2
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	// proxy the response from the world back to the subprocess
	verbosef("replying to %v %v %v with %v (content length %d) ...", req.Method, req.URL, req.Proto, resp.Status, resp.ContentLength)
	err = resp.Write(conn)
	if err != nil {
		errorf("error writing response to tls server conn: %v", err)
		return
	}

	verbosef("finished replying to %v %v %v (%d bytes) with %v %v (%d bytes)",
		req.Method, req.URL, req.Proto, reqbody.Len(), resp.Status, resp.Proto, respbody.Len())

	// log the request (do not do this earlier since reqbody may not be compete until now)
	reqcolor := color.New(color.FgBlue, color.Bold)
	reqcolor.Printf("---> %v %v\n", req.Method, req.URL)

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
	respcolor.Printf("<--- %v %v (%d bytes)\n", resp.StatusCode, req.URL, respbody.Len())

	// make the summary the we will log to disk and expose via the API
	call := HTTPCall{
		Request: HTTPRequest{
			Method:      req.Method,
			URL:         req.URL.String(),
			Host:        req.Host,
			ContentType: req.Header.Get("Content-Type"),
		},
		Response: HTTPResponse{
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Length:     int64(respbody.Len()),
		},
		TotalBytes: counts.read + counts.written,
	}

	verbosef("notifying http watchers %v %v %v (%d bytes)...", req.Method, req.URL, resp.Status, resp.ContentLength)
	notifyHTTP(&call)
}

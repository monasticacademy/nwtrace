package main

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/miekg/dns"
)

// handle a DNS query payload here is the application-level UDP payload
func handleDNS(ctx context.Context, w io.Writer, payload []byte) {
	var req dns.Msg
	err := req.Unpack(payload)
	if err != nil {
		errorf("error unpacking dns packet: %v, ignoring", err)
		return
	}

	if req.Opcode != dns.OpcodeQuery {
		verbosef("ignoring a dns query with non-query opcode (%v)", req.Opcode)
		return
	}

	// resolve the query
	rrs, err := handleDNSQuery(ctx, &req)
	if err != nil {
		verbosef("dns failed for %v with error: %v, sending a response with empty answer", req, err.Error())
		// do not abort here, continue on and send a reply with no answer
		// because the client might easily have tried to resolve a non-existent
		// hostname
	}

	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.Answer = rrs

	// serialize the response
	buf, err := resp.Pack()
	if err != nil {
		errorf("error serializing dns response: %v, abandoning...", err)
		return
	}

	// always send the entire buffer in a single Write() since UDP writes one packet per call to Write()
	verbosef("responding to DNS request with %d bytes...", len(buf))
	_, err = w.Write(buf)
	if err != nil {
		errorf("error writing dns response: %v, abandoning...", err)
		return
	}
	verbosef("done responding to DNS request (sent %d bytes)", len(buf))
}

// handleDNSQuery resolves IPv4 hostnames according to net.DefaultResolver
func handleDNSQuery(ctx context.Context, req *dns.Msg) ([]dns.RR, error) {
	const upstreamDNS = "1.1.1.1:53" // TODO: get from resolv.conf and nsswitch.conf

	if len(req.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := req.Question[0]
	verbosef("got dns request for %v", question.Name)

	// handle the request ourselves
	switch question.Qtype {
	case dns.TypeA:
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", question.Name)
		if err != nil {
			return nil, fmt.Errorf("the default resolver said: %w", err)
		}

		verbosef("resolved %v to %v with default resolver", question.Name, ips)

		var rrs []dns.RR
		for _, ip := range ips {
			rrline := fmt.Sprintf("%s A %s", question.Name, ip)
			rr, err := dns.NewRR(rrline)
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}
		return rrs, nil
	}

	verbose("proxying non-A request to upstream DNS server...")

	// proxy the request to another server
	request := new(dns.Msg)
	req.CopyTo(request)
	request.Question = []dns.Question{question}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(request, upstreamDNS)
	if err != nil {
		return nil, err
	}

	verbosef("got answer from upstream dns server with %d answers", len(response.Answer))

	if len(response.Answer) > 0 {
		return response.Answer, nil
	}
	return nil, fmt.Errorf("not found")
}

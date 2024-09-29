package main

import (
	"fmt"
	"log"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/miekg/dns"
)

const upstreamDNS = "1.1.1.1:53" // TODO: get from resolv.conf and nsswitch.conf

func handle(requestMsg *dns.Msg) (dns.RR, error) {
	if len(requestMsg.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := requestMsg.Question[0]
	log.Printf("got dns request for %v for %v", question.Qtype, question.Name)

	// handle the request ourselves
	if question.Qtype == dns.TypeA && question.Name == "example.com." {
		log.Println("responding with example.com IP 44.33.22.11")
		ip := "44.33.22.11"
		rrline := fmt.Sprintf("%s A %s", question.Name, ip)
		answer, err := dns.NewRR(rrline)
		if err != nil {
			log.Printf("error parsing %q: %v", rrline, err)
			return nil, fmt.Errorf("error parsing rr: %w", err)
		}
		return answer, nil
	}

	log.Println("proxying the request...")

	// proxy the request to another server
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{question}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(queryMsg, upstreamDNS)
	if err != nil {
		return nil, err
	}

	log.Printf("got answer from upstream dns server with %d answers", len(response.Answer))

	if len(response.Answer) > 0 {
		return response.Answer[0], nil
	}
	return nil, fmt.Errorf("not found")
}

func Main() error {
	var args struct {
		Port string `arg:"positional"`
	}
	arg.MustParse(&args)

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		switch req.Opcode {
		case dns.OpcodeQuery:
			rr, err := handle(req)
			if err != nil {
				log.Printf("dns failed for %s with error: %v, continuing...", req, err.Error())
				// do not abort here, continue on
			}

			resp := new(dns.Msg)
			resp.SetReply(req)
			if rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}

			w.WriteMsg(resp)
		}
	})

	server := &dns.Server{Addr: args.Port, Net: "udp"}
	log.Printf("listening on %v...", server.Addr)
	return server.ListenAndServe()
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

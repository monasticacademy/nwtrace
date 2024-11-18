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

func dnsTypeCode(t uint16) string {
	switch t {
	case dns.TypeNone:
		return "<None>"
	case dns.TypeA:
		return "A"
	case dns.TypeNS:
		return "NS"
	case dns.TypeMD:
		return "MD"
	case dns.TypeMF:
		return "MF"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypeMB:
		return "MB"
	case dns.TypeMG:
		return "MG"
	case dns.TypeMR:
		return "MR"
	case dns.TypeNULL:
		return "NULL"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeHINFO:
		return "HINFO"
	case dns.TypeMINFO:
		return "MINFO"
	case dns.TypeMX:
		return "MX"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeRP:
		return "RP"
	case dns.TypeAFSDB:
		return "AFSDB"
	case dns.TypeX25:
		return "X25"
	case dns.TypeISDN:
		return "ISDN"
	case dns.TypeRT:
		return "RT"
	case dns.TypeNSAPPTR:
		return "NSAPPTR"
	case dns.TypeSIG:
		return "SIG"
	case dns.TypeKEY:
		return "KEY"
	case dns.TypePX:
		return "PX"
	case dns.TypeGPOS:
		return "GPOS"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeLOC:
		return "LOC"
	case dns.TypeNXT:
		return "NXT"
	case dns.TypeEID:
		return "EID"
	case dns.TypeNIMLOC:
		return "NIMLOC"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeATMA:
		return "ATMA"
	case dns.TypeNAPTR:
		return "NAPTR"
	case dns.TypeKX:
		return "KX"
	case dns.TypeCERT:
		return "CERT"
	case dns.TypeDNAME:
		return "DNAME"
	case dns.TypeOPT:
		return "OPT"
	case dns.TypeAPL:
		return "APL"
	case dns.TypeDS:
		return "DS"
	case dns.TypeSSHFP:
		return "SSHFP"
	case dns.TypeIPSECKEY:
		return "IPSECKEY"
	case dns.TypeRRSIG:
		return "RRSIG"
	case dns.TypeNSEC:
		return "NSEC"
	case dns.TypeDNSKEY:
		return "DNSKEY"
	case dns.TypeDHCID:
		return "DHCID"
	case dns.TypeNSEC3:
		return "NSEC3"
	case dns.TypeNSEC3PARAM:
		return "NSEC3PARAM"
	case dns.TypeTLSA:
		return "TLSA"
	case dns.TypeSMIMEA:
		return "SMIMEA"
	case dns.TypeHIP:
		return "HIP"
	case dns.TypeNINFO:
		return "NINFO"
	case dns.TypeRKEY:
		return "RKEY"
	case dns.TypeTALINK:
		return "TALINK"
	case dns.TypeCDS:
		return "CDS"
	case dns.TypeCDNSKEY:
		return "CDNSKEY"
	case dns.TypeOPENPGPKEY:
		return "OPENPGPKEY"
	case dns.TypeCSYNC:
		return "CSYNC"
	case dns.TypeZONEMD:
		return "ZONEMD"
	case dns.TypeSVCB:
		return "SVCB"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypeSPF:
		return "SPF"
	case dns.TypeUINFO:
		return "UINFO"
	case dns.TypeUID:
		return "UID"
	case dns.TypeGID:
		return "GID"
	case dns.TypeUNSPEC:
		return "UNSPEC"
	case dns.TypeNID:
		return "NID"
	case dns.TypeL32:
		return "L32"
	case dns.TypeL64:
		return "L64"
	case dns.TypeLP:
		return "LP"
	case dns.TypeEUI48:
		return "EUI48"
	case dns.TypeEUI64:
		return "EUI64"
	case dns.TypeNXNAME:
		return "NXNAME"
	case dns.TypeURI:
		return "URI"
	case dns.TypeCAA:
		return "CAA"
	case dns.TypeAVC:
		return "AVC"
	case dns.TypeAMTRELAY:
		return "AMTRELAY"
	case dns.TypeTKEY:
		return "TKEY"
	case dns.TypeTSIG:
		return "TSIG"
	case dns.TypeIXFR:
		return "IXFR"
	case dns.TypeAXFR:
		return "AXFR"
	case dns.TypeMAILB:
		return "MAILB"
	case dns.TypeMAILA:
		return "MAILA"
	case dns.TypeANY:
		return "ANY"
	case dns.TypeTA:
		return "TA"
	case dns.TypeDLV:
		return "DLV"
	case dns.TypeReserved:
		return "Reserved"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// handleDNSQuery resolves IPv4 hostnames according to net.DefaultResolver
func handleDNSQuery(ctx context.Context, req *dns.Msg) ([]dns.RR, error) {
	const upstreamDNS = "1.1.1.1:53" // TODO: get from resolv.conf and nsswitch.conf

	if len(req.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := req.Question[0]
	verbosef("got dns request for %v (%v)", question.Name, dnsTypeCode(question.Qtype))

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
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, ip))
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}
		return rrs, nil
	case dns.TypeAAAA:
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", question.Name)
		if err != nil {
			return nil, fmt.Errorf("the default resolver said: %w", err)
		}

		verbosef("resolved %v to %v with default resolver", question.Name, ips)

		var rrs []dns.RR
		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", question.Name, ip))
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

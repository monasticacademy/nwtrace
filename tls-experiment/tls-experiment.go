package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

func Main() error {
	// create a CA template for the call to CreateCertificate below -- note that this is not a valid
	// x509 certificate until it is signed with the key generated below, inside x509.CreateCertificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Center for Certificate Authorities"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Diego"},
			StreetAddress: []string{"1 Page Rd"},
			PostalCode:    []string{"90210"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// create and serialize a certificate from the template
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// parse the bytes to gives us an actual CA
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return fmt.Errorf("error parsing serialized certificate: %w", err)
	}

	// create a certificate template for the call to CreateCertificate below -- note that this is not a valid
	// x509 certificate until it is signed with the key generated below, inside x509.CreateCertificate
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Center for Certificate Authorities"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Diego"},
			StreetAddress: []string{"1 Page Rd"},
			PostalCode:    []string{"90210"},
		},
		DNSNames:     []string{"example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// generate a key for the certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// create the certificate with the CA as the parent
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// caPrivKeyPEM := new(bytes.Buffer)
	// pem.Encode(caPrivKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	// })

	// write the certificate authority to a temporary file
	crtPath := "/tmp/httptap.crt"
	f, err := os.Create(crtPath)
	if err != nil {
		return err
	}

	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return fmt.Errorf("error encoding CA to pem: %w", err)
	}
	_ = f.Close()

	log.Printf("wrote CA to %v", crtPath)

	// start an HTTP server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certBytes},
			PrivateKey:  certPrivKey,
		}},
	}

	server.StartTLS()
	defer server.Close()

	// communicate with the server using an http.Client configured to trust our CA
	certpool := x509.NewCertPool()
	certpool.AddCert(ca)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certpool,
		},
	}
	http := http.Client{
		Transport: transport,
	}
	resp, err := http.Get(server.URL)
	if err != nil {
		return err
	}

	// verify the response
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body != "success!" {
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

// use SSL_CERT_FILE
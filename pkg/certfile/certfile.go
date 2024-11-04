package certfile

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// WritePEM writes an x509 certificate to a PEM file
func WritePEM(path string, certificate *x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
}

// WritePKCS12 writes an x509 certificate to PKCS12 file
func WritePKCS12(path string, certificate *x509.Certificate) error {
	truststore, err := pkcs12.Passwordless.EncodeTrustStore([]*x509.Certificate{certificate}, "")
	if err != nil {
		return fmt.Errorf("error encoding certificate authority in pkcs12 format: %w", err)
	}

	return os.WriteFile(path, truststore, os.ModePerm)
}

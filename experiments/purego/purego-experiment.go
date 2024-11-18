package main

import (
	"log"
	"os"

	"github.com/ebitengine/purego"
)

const (
	OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004
	OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008
)

func Main() error {
	libcrypto, err := purego.Dlopen("libcrypto.so", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}

	var X509_get_default_cert_dir_env func() string
	var X509_get_default_cert_dir func() string

	purego.RegisterLibFunc(&X509_get_default_cert_dir_env, libcrypto, "X509_get_default_cert_dir_env")
	purego.RegisterLibFunc(&X509_get_default_cert_dir, libcrypto, "X509_get_default_cert_dir")

	log.Println(X509_get_default_cert_dir_env())
	log.Println(X509_get_default_cert_dir())

	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}

package opensslpaths

import (
	"reflect"
	"sync"

	"github.com/ebitengine/purego"
)

// if libcrypto.so can be loaded then these function pointers will be populated
type libcryptoFuncs struct {
	X509_get_default_cert_dir      func() string // default cert dir
	X509_get_default_cert_dir_env  func() string // name of environment variable controlling the above
	X509_get_default_cert_file     func() string // default cert file
	X509_get_default_cert_file_env func() string // name of environment variable controlling the above
}

var libcrypto = sync.OnceValue[*libcryptoFuncs](func() *libcryptoFuncs {
	defer recover()

	libcrypto, err := purego.Dlopen("libcrypto.so", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil
	}

	var funcs libcryptoFuncs
	v := reflect.ValueOf(&funcs).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		purego.RegisterLibFunc(v.Field(i).Addr().Interface(), libcrypto, t.Field(i).Name)
	}

	return &funcs
})

// Get the default certificate dir configured for openssl, or empty string if openssl is not installed or cannot be loaded
func DefaultCertFile() string {
	defer recover()
	if lib := libcrypto(); lib != nil {
		return lib.X509_get_default_cert_file()
	}
	return ""
}

// Get the name of the environment variable that controls the default certificate dir, or empty string if openssl is not installed or cannot be loaded
func DefaultCertFileEnv() string {
	defer recover()
	if lib := libcrypto(); lib != nil {
		return lib.X509_get_default_cert_file_env()
	}
	return ""

}

// Get the default certificate dir configured for openssl, or empty string if openssl is not installed or cannot be loaded
func DefaultCertDir() string {
	defer recover()
	if lib := libcrypto(); lib != nil {
		return lib.X509_get_default_cert_dir()
	}
	return ""
}

// Get the name of the environment variable that controls the default certificate dir, or empty string if openssl is not installed or cannot be loaded
func DefaultCertDirEnv() string {
	defer recover()
	if lib := libcrypto(); lib != nil {
		return lib.X509_get_default_cert_dir_env()
	}
	return ""
}

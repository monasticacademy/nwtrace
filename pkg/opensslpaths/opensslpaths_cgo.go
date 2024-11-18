//go:build cgo
// +build cgo

package opensslpaths

import (
	"reflect"
	"sync"

	"github.com/ebitengine/purego"
)

// Purego provides a way to load external libraries without cgo, but it causes those
// executables to be dynamically linked to libc, which defeats the purpose a bit.
// Here we use it only when CGO is enabled because what we are using it for is loading
// dynamic libraries and falling back to default behavior when they are not found.

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

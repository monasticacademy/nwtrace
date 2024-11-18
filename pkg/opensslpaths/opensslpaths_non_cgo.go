//go:build !cgo
// +build !cgo

package opensslpaths

import (
	"sync"
)

var libcrypto = sync.OnceValue[*libcryptoFuncs](func() *libcryptoFuncs {
	return nil
})

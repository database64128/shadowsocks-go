package magic

import (
	_ "unsafe"
)

//go:linkname XORBytes crypto/cipher.xorBytes
//go:noescape
func XORBytes(dst, a, b []byte) int

//go:linkname XORWords crypto/cipher.xorWords
//go:noescape
func XORWords(dst, a, b []byte)

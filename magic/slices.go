package magic

import _ "unsafe"

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
//
//go:linkname SliceForAppend crypto/aes.sliceForAppend
func SliceForAppend(in []byte, n int) (head, tail []byte)

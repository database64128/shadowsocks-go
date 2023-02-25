package magic

import _ "unsafe"

//go:linkname Fastrand runtime.fastrand
func Fastrand() uint32

//go:linkname Fastrandn runtime.fastrandn
func Fastrandn(n uint32) uint32

//go:linkname Fastrand64 runtime.fastrand64
func Fastrand64() uint64

//go:linkname Fastrandu runtime.fastrandu
func Fastrandu() uint

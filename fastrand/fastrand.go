package fastrand

import (
	"math/bits"
	"unsafe"
	_ "unsafe"
)

//go:linkname Uint32 runtime.fastrand
func Uint32() uint32

//go:linkname Uint32n runtime.fastrandn
func Uint32n(n uint32) uint32

//go:linkname Uint64 runtime.fastrand64
func Uint64() uint64

//go:linkname Uint runtime.fastrandu
func Uint() uint

// Fastrand is a fast random number generator based on wyrand.
type Fastrand uint64

// New returns a new [Fastrand] seeded from the Go runtime's fastrand.
func New() Fastrand {
	return Fastrand(Uint64())
}

// Uint64 returns a random uint64.
func (f *Fastrand) Uint64() uint64 {
	*f += 0xa0761d6478bd642f
	hi, lo := bits.Mul64(uint64(*f), uint64(*f^0xe7037ed1a0b428db))
	return hi ^ lo
}

// Fill fills b with random bytes.
func (f *Fastrand) Fill(b []byte) {
	for len(b) >= 8 {
		*(*uint64)(unsafe.Pointer(&b[0])) = f.Uint64()
		b = b[8:]
	}

	if len(b) > 0 {
		r := f.Uint64()

		if len(b) >= 4 {
			*(*uint32)(unsafe.Pointer(&b[0])) = uint32(r)
			b = b[4:]
			r >>= 32
		}

		if len(b) >= 2 {
			*(*uint16)(unsafe.Pointer(&b[0])) = uint16(r)
			b = b[2:]
			r >>= 16
		}

		if len(b) > 0 {
			b[0] = uint8(r)
		}
	}
}

// Read fills b with random bytes and returns len(b) and nil.
func (f *Fastrand) Read(b []byte) (int, error) {
	f.Fill(b)
	return len(b), nil
}

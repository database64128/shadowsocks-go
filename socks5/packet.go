package socks5

import "errors"

var ErrFragmentationNotSupported = errors.New("packet fragmentation is not supported")

// WritePacketHeader writes RSV and FRAG to the beginning of b.
// The length of b must be at least 3 bytes.
func WritePacketHeader(b []byte) {
	b[0] = 0 // RSV
	b[1] = 0 // RSV
	b[2] = 0 // FRAG
}

// ValidatePacketHeader validates RSV and FRAG at the beginning of b.
// The length of b must be at least 3 bytes.
func ValidatePacketHeader(b []byte) error {
	if b[2] != 0 {
		return ErrFragmentationNotSupported
	}
	return nil
}

package zerocopy

// Packer processes raw payload into packets.
type Packer interface {
	Headroom

	// PackInPlace packs the payload in-place into a packet and returns packet start offset, packet length,
	// or an error if packing fails.
	PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error)
}

// Unpacker processes packets into raw payload.
type Unpacker interface {
	Headroom

	// UnpackInPlace unpacks the packet in-place and returns payload start offset, payload length,
	// or an error if unpacking fails.
	UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error)
}

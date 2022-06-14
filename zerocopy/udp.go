package zerocopy

type UDPClient interface {
	NewSession() (Packer, Unpacker, error)
}

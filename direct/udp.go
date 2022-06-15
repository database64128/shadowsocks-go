package direct

import "github.com/database64128/shadowsocks-go/zerocopy"

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	p *DirectPacketPackUnpacker
}

func NewUDPClient() *UDPClient {
	return &UDPClient{
		p: NewDirectClient(),
	}
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *UDPClient) NewSession() (zerocopy.Packer, zerocopy.Unpacker, error) {
	return c.p, c.p, nil
}

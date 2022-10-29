package direct

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func NewUDPClient(name string, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	p := NewDirectPacketClientPackUnpacker(mtu)
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(mtu, netip.IPv4Unspecified())
	return zerocopy.NewSimpleUDPClient(zerocopy.ZeroHeadroom{}, p, p, name, maxPacketSize, fwmark)
}

func NewShadowsocksNoneUDPClient(addrPort netip.AddrPort, name string, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr())
	packer := NewShadowsocksNonePacketClientPacker(addrPort, maxPacketSize)
	unpacker := NewShadowsocksNonePacketClientUnpacker(addrPort)
	return zerocopy.NewSimpleUDPClient(ShadowsocksNonePacketClientMessageHeadroom{}, packer, unpacker, name, maxPacketSize, fwmark)
}

// NewSocks5UDPClient creates a SOCKS5 UDP client.
//
// Technically, each UDP session should be preceded by a UDP ASSOCIATE request.
// But most censorship circumvention programs do not require this.
// So we just skip this little ritual.
func NewSocks5UDPClient(addrPort netip.AddrPort, name string, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr())
	packer := NewSocks5PacketClientPacker(addrPort, maxPacketSize)
	unpacker := NewSocks5PacketClientUnpacker(addrPort)
	return zerocopy.NewSimpleUDPClient(Socks5PacketClientMessageHeadroom{}, packer, unpacker, name, maxPacketSize, fwmark)
}

// DirectUDPNATServer implements the zerocopy UDPNATServer interface.
type DirectUDPNATServer struct {
	zerocopy.ZeroHeadroom

	p *DirectPacketServerPackUnpacker
}

func NewDirectUDPNATServer(targetAddr conn.Addr, targetAddrOnly bool) *DirectUDPNATServer {
	return &DirectUDPNATServer{
		p: NewDirectPacketServerPackUnpacker(targetAddr, targetAddrOnly),
	}
}

// NewSession implements the zerocopy.UDPNATServer NewSession method.
func (s *DirectUDPNATServer) NewSession() (zerocopy.ServerPacker, zerocopy.ServerUnpacker, error) {
	return s.p, s.p, nil
}

// ShadowsocksNoneUDPNATServer implements the zerocopy UDPNATServer interface.
type ShadowsocksNoneUDPNATServer struct {
	ShadowsocksNonePacketClientMessageHeadroom
}

// NewSession implements the zerocopy.UDPNATServer NewSession method.
func (ShadowsocksNoneUDPNATServer) NewSession() (zerocopy.ServerPacker, zerocopy.ServerUnpacker, error) {
	return ShadowsocksNonePacketServerPacker{}, &ShadowsocksNonePacketServerUnpacker{}, nil
}

// Socks5UDPNATServer implements the zerocopy UDPNATServer interface.
type Socks5UDPNATServer struct {
	Socks5PacketClientMessageHeadroom
}

// NewSession implements the zerocopy.UDPNATServer NewSession method.
func (Socks5UDPNATServer) NewSession() (zerocopy.ServerPacker, zerocopy.ServerUnpacker, error) {
	return Socks5PacketServerPacker{}, &Socks5PacketServerUnpacker{}, nil
}

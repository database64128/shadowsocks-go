package direct

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func NewUDPClient(mtu, fwmark int, preferIPv6 bool) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(NewDirectPacketClientPackUnpacker(mtu, preferIPv6), zerocopy.MaxPacketSizeForAddr(mtu, netip.IPv4Unspecified()), fwmark, 0, 0)
}

func NewShadowsocksNoneUDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr())
	return zerocopy.NewSimpleUDPClient(NewShadowsocksNonePacketClientPackUnpacker(addrPort, maxPacketSize), maxPacketSize, fwmark, socks5.MaxAddrLen, 0)
}

// NewSocks5UDPClient creates a SOCKS5 UDP client.
//
// Technically, each UDP session should be preceded by a UDP ASSOCIATE request.
// But most censorship circumvention programs do not require this.
// So we just skip this little ritual.
func NewSocks5UDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr())
	return zerocopy.NewSimpleUDPClient(NewSocks5PacketClientPackUnpacker(addrPort, maxPacketSize), maxPacketSize, fwmark, 3+socks5.MaxAddrLen, 0)
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
	ShadowsocksNonePacketHeadroom
}

// NewSession implements the zerocopy.UDPNATServer NewSession method.
func (s *ShadowsocksNoneUDPNATServer) NewSession() (zerocopy.ServerPacker, zerocopy.ServerUnpacker, error) {
	var p ShadowsocksNonePacketServerPackUnpacker
	return &p, &p, nil
}

// Socks5UDPNATServer implements the zerocopy UDPNATServer interface.
type Socks5UDPNATServer struct {
	Socks5PacketHeadroom
}

// NewSession implements the zerocopy.UDPNATServer NewSession method.
func (s *Socks5UDPNATServer) NewSession() (zerocopy.ServerPacker, zerocopy.ServerUnpacker, error) {
	var p Socks5PacketServerPackUnpacker
	return &p, &p, nil
}

var (
	DefaultShadowsocksNoneUDPNATServer = &ShadowsocksNoneUDPNATServer{}
	DefaultSocks5UDPNATServer          = &Socks5UDPNATServer{}
)

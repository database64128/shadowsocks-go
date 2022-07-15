package direct

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func NewUDPClient(mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultDirectClientPacketPackUnpacker, netip.AddrPort{}, false, mtu, fwmark, 0, 0)
}

func NewShadowsocksNoneUDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultShadowsocksNonePacketPackUnpacker, addrPort, true, mtu, fwmark, socks5.MaxAddrLen, 0)
}

// NewSocks5UDPClient creates a SOCKS5 UDP client.
//
// Technically, each UDP session should be preceded by a UDP ASSOCIATE request.
// But most censorship circumvention programs do not require this.
// So we just skip this little ritual.
func NewSocks5UDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultSocks5PacketPackUnpacker, addrPort, true, mtu, fwmark, 3+socks5.MaxAddrLen, 0)
}

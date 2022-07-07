package direct

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

func NewUDPClient(mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultDirectClientPacketPackUnpacker, netip.AddrPort{}, mtu, fwmark, false)
}

func NewShadowsocksNoneUDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultShadowsocksNonePacketPackUnpacker, addrPort, mtu, fwmark, true)
}

// NewSocks5UDPClient creates a SOCKS5 UDP client.
//
// Technically, each UDP session should be preceded by a UDP ASSOCIATE request.
// But most censorship circumvention programs do not require this.
// So we just skip this little ritual.
func NewSocks5UDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultSocks5PacketPackUnpacker, addrPort, mtu, fwmark, true)
}

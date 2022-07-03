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

func NewSocks5UDPClient(addrPort netip.AddrPort, mtu, fwmark int) *zerocopy.SimpleUDPClient {
	return zerocopy.NewSimpleUDPClient(&DefaultSocks5PacketPackUnpacker, addrPort, mtu, fwmark, true)
}

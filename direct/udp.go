package direct

import "github.com/database64128/shadowsocks-go/zerocopy"

var (
	DefaultDirectUDPClient          = zerocopy.NewSimpleUDPClient(&DefaultDirectClientPacketPackUnpacker)
	DefaultShadowsocksNoneUDPClient = zerocopy.NewSimpleUDPClient(&DefaultShadowsocksNonePacketPackUnpacker)
	DefaultSocks5UDPClient          = zerocopy.NewSimpleUDPClient(&DefaultSocks5PacketPackUnpacker)
)

package direct

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

const (
	mtu        = 1500
	packetSize = 1452
)

var (
	targetAddr     = conn.AddrFromIPPort(targetAddrPort)
	targetAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	serverAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 1080)
)

func TestDirectPacketPackUnpacker(t *testing.T) {
	c := NewDirectPacketClientPackUnpacker(mtu, true)
	s := NewDirectPacketServerPackUnpacker(targetAddr, false) // Cheat a little bit, because we have to. :P
	zerocopy.ClientServerPackUnpackerTestFunc(t, c, s)
}

func TestShadowsocksNonePacketPackUnpacker(t *testing.T) {
	c := NewShadowsocksNonePacketClientPackUnpacker(serverAddrPort, packetSize)
	zerocopy.ClientServerPackUnpackerTestFunc(t, c, &ShadowsocksNonePacketServerPackUnpacker{})
}

func TestSocks5PacketPackUnpacker(t *testing.T) {
	c := NewSocks5PacketClientPackUnpacker(serverAddrPort, packetSize)
	zerocopy.ClientServerPackUnpackerTestFunc(t, c, &Socks5PacketServerPackUnpacker{})
}

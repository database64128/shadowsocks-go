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
	c := NewDirectPacketClientPackUnpacker(mtu)
	s := NewDirectPacketServerPackUnpacker(targetAddr, false) // Cheat a little bit, because we have to. :P
	zerocopy.ClientServerPackerUnpackerTestFunc(t, c, c, s, s)
}

func TestShadowsocksNonePacketPackUnpacker(t *testing.T) {
	clientPacker := NewShadowsocksNonePacketClientPacker(serverAddrPort, packetSize)
	clientUnpacker := NewShadowsocksNonePacketClientUnpacker(serverAddrPort)
	zerocopy.ClientServerPackerUnpackerTestFunc(t, clientPacker, clientUnpacker, ShadowsocksNonePacketServerPacker{}, &ShadowsocksNonePacketServerUnpacker{})
}

func TestSocks5PacketPackUnpacker(t *testing.T) {
	clientPacker := NewSocks5PacketClientPacker(serverAddrPort, packetSize)
	clientUnpacker := NewSocks5PacketClientUnpacker(serverAddrPort)
	zerocopy.ClientServerPackerUnpackerTestFunc(t, clientPacker, clientUnpacker, Socks5PacketServerPacker{}, &Socks5PacketServerUnpacker{})
}

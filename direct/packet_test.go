package direct

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func TestDirectPacketPackUnpacker(t *testing.T) {
	// Cheat a little bit, because we have to. :P
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	c := NewDirectClient()
	s := NewDirectServer(targetAddr)

	zerocopy.PackerUnpackerTestFunc(t, c, s)
}

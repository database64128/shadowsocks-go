package dns

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func testResolver(t *testing.T, name string, serverAddrPort netip.AddrPort, tcpClient netio.StreamClient, udpClient zerocopy.UDPClient, logger *zap.Logger) {
	r := NewResolver(name, defaultCacheSize, serverAddrPort, tcpClient, udpClient, logger)
	ctx := t.Context()

	// Uncached lookup.
	uncachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(uncachedResult.a) == 0 {
		t.Error("Expected at least one IPv4 address")
	}
	if len(uncachedResult.aaaa) == 0 {
		t.Error("Expected at least one IPv6 address")
	}

	// Cached lookup.
	cachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if uncachedResult.expiresAt != cachedResult.expiresAt {
		t.Error("TTL mismatch")
	}
}

func TestResolver(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	serverAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)
	tcpClientConfig := netio.TCPClientConfig{
		Name:    "direct",
		Network: "tcp",
		Dialer:  conn.DefaultTCPDialer,
	}
	tcpClient := tcpClientConfig.NewTCPClient()
	udpClient := direct.NewDirectUDPClient("direct", "ip", 1500, conn.DefaultUDPClientListenConfig)

	t.Run("UDP", func(t *testing.T) {
		testResolver(t, "UDP", serverAddrPort, nil, udpClient, logger)
	})

	t.Run("TCP", func(t *testing.T) {
		testResolver(t, "TCP", serverAddrPort, tcpClient, nil, logger)
	})
}

package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

func testResolver(t *testing.T, ctx context.Context, name string, serverAddrPort netip.AddrPort, tcpClient zerocopy.TCPClient, udpClient zerocopy.UDPClient, logger *zap.Logger) {
	r := NewResolver(name, serverAddrPort, tcpClient, udpClient, logger)

	// Uncached lookup.
	uncachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(uncachedResult.IPv4) == 0 {
		t.Error("Expected at least one IPv4 address")
	}
	if len(uncachedResult.IPv6) == 0 {
		t.Error("Expected at least one IPv6 address")
	}

	// Cached lookup.
	cachedResult, err := r.Lookup(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if uncachedResult.TTL != cachedResult.TTL {
		t.Error("TTL mismatch")
	}
}

func TestResolver(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	ctx := context.Background()
	serverAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)
	tcpClient := direct.NewTCPClient("direct", conn.DefaultTCPDialer)
	udpClient := direct.NewDirectUDPClient("direct", 1500, conn.DefaultUDPClientListenConfig)

	t.Run("UDP", func(t *testing.T) {
		testResolver(t, ctx, "UDP", serverAddrPort, nil, udpClient, logger)
	})

	t.Run("TCP", func(t *testing.T) {
		testResolver(t, ctx, "TCP", serverAddrPort, tcpClient, nil, logger)
	})
}

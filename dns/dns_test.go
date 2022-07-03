package dns

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

func testResolver(t *testing.T, serverAddrPort netip.AddrPort, tcpClient zerocopy.TCPClient, udpClient zerocopy.UDPClient, logger *zap.Logger) {
	r := NewResolver(serverAddrPort, tcpClient, udpClient, logger)

	// Uncached lookup.
	uncachedResult, err := r.Lookup("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Cached lookup.
	cachedResult, err := r.Lookup("example.com")
	if err != nil {
		t.Fatal(err)
	}

	if uncachedResult.TTL != cachedResult.TTL {
		t.Error("TTL mismatch")
	}
}

func TestResolver(t *testing.T) {
	logger, err := logging.NewProductionConsole(false, "debug")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	serverAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)
	tcpClient := direct.NewTCPClient(true, 0)
	udpClient := direct.NewUDPClient(1500, 0)

	// Test UDP.
	testResolver(t, serverAddrPort, nil, udpClient, logger)

	// Test TCP.
	testResolver(t, serverAddrPort, tcpClient, nil, logger)
}

package http

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

func TestHttpStreamReadWriter(t *testing.T) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *direct.DirectStreamReadWriter
		s                *direct.DirectStreamReadWriter
		serverTargetAddr conn.Addr
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewHttpStreamClientReadWriter(pl, clientTargetAddr)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewHttpStreamServerReadWriter(pr, logger)
		ctrlCh <- struct{}{}
	}()

	<-ctrlCh
	<-ctrlCh
	if cerr != nil {
		t.Fatal(cerr)
	}
	if serr != nil {
		t.Fatal(serr)
	}

	if clientTargetAddr != serverTargetAddr {
		t.Errorf("Target address mismatch: c: %s, s: %s", clientTargetAddr, serverTargetAddr)
	}

	zerocopy.ReadWriterTestFunc(t, c, s)
}

func testHostHeaderToDomainPort(t *testing.T, host, expectedDomain string, expectedPort uint16) {
	addr, err := hostHeaderToAddr(host)
	if err != nil {
		t.Errorf("Failed to parse %s: %s", host, err)
	}
	if domain := addr.Domain(); domain != expectedDomain {
		t.Errorf("Expected domain %s, got %s", expectedDomain, domain)
	}
	if port := addr.Port(); port != expectedPort {
		t.Errorf("Expected port %d, got %d", expectedPort, port)
	}
}

func testHostHeaderToIPPort(t *testing.T, host string, expectedAddrPort netip.AddrPort) {
	addr, err := hostHeaderToAddr(host)
	if err != nil {
		t.Errorf("Failed to parse %s: %s", host, err)
	}
	if addrPort := addr.IPPort(); addrPort != expectedAddrPort {
		t.Errorf("Expected addrPort %s, got %s", expectedAddrPort, addrPort)
	}
}

func testHostHeaderToError(t *testing.T, host string, expectedErr error) {
	_, err := hostHeaderToAddr(host)
	if err != expectedErr {
		t.Errorf("Expected error %s, got %s", expectedErr, err)
	}
}

func TestHostHeaderToAddr(t *testing.T) {
	testHostHeaderToDomainPort(t, "example.com", "example.com", 80)
	testHostHeaderToDomainPort(t, "example.com:443", "example.com", 443)

	addr4 := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	testHostHeaderToIPPort(t, "1.1.1.1", netip.AddrPortFrom(addr4, 80))
	testHostHeaderToIPPort(t, "1.1.1.1:443", netip.AddrPortFrom(addr4, 443))

	addr6 := netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11})
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]", netip.AddrPortFrom(addr6, 80))
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]:443", netip.AddrPortFrom(addr6, 443))

	testHostHeaderToError(t, "", errEmptyHostHeader)
}

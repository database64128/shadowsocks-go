package http

import (
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap/zaptest"
)

func TestHttpStreamReadWriter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *direct.DirectStreamReadWriter
		s                *direct.DirectStreamReadWriter
		serverTargetAddr conn.Addr
		cerr, serr       error
	)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		c, cerr = NewHttpStreamClientReadWriter(pl, clientTargetAddr)
		wg.Done()
	}()

	go func() {
		s, serverTargetAddr, serr = NewHttpStreamServerReadWriter(pr, logger)
		wg.Done()
	}()

	wg.Wait()
	if cerr != nil {
		t.Fatal(cerr)
	}
	if serr != nil {
		t.Fatal(serr)
	}

	if !clientTargetAddr.Equals(serverTargetAddr) {
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

	addr6 := netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 14: 0x11, 15: 0x11})
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]", netip.AddrPortFrom(addr6, 80))
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]:443", netip.AddrPortFrom(addr6, 443))

	testHostHeaderToError(t, "", errEmptyHostHeader)
}

func TestRemoveConnectionSpecificFields(t *testing.T) {
	header := http.Header{
		"Connection":        []string{"keep-alive, upgrade, drop-this"},
		"Proxy-Connection":  []string{"Keep-Alive"},
		"Keep-Alive":        []string{"timeout=5, max=1000"},
		"Upgrade":           []string{"websocket"},
		"Drop-This":         []string{"Drop me!"},
		"Keep-This":         []string{"Keep me!"},
		"Te":                []string{"trailers"},
		"Transfer-Encoding": []string{"chunked"},
	}

	expectedHeader := http.Header{
		"Upgrade":   []string{"websocket"},
		"Keep-This": []string{"Keep me!"},
	}

	trailer := http.Header{
		"Drop-This": []string{"Drop me!"},
		"Keep-This": []string{"Keep me!"},
	}

	expectedTrailer := http.Header{
		"Keep-This": []string{"Keep me!"},
	}

	removeConnectionSpecificFields(header, trailer)

	if !maps.EqualFunc(header, expectedHeader, slices.Equal) {
		t.Errorf("header = %v, expected %v", header, expectedHeader)
	}

	if !maps.EqualFunc(trailer, expectedTrailer, slices.Equal) {
		t.Errorf("trailer = %v, expected %v", trailer, expectedTrailer)
	}
}

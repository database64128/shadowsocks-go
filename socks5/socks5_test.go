package socks5

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
)

// Test IPv4 address.
var (
	addr4         = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4addrport = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1080)
	addr4str      = "127.0.0.1:1080"
)

// Test IPv4-mapped IPv6 address.
var (
	addr4in6         = addr4
	addr4in6addrport = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}), 1080)
	addr4in6str      = "[::ffff:127.0.0.1]:1080"
)

// Test IPv6 address.
var (
	addr6         = []byte{AtypIPv6, 0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e, 4, 56}
	addr6addrport = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e}), 1080)
	addr6str      = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

// Test domain name.
var (
	addrDomainName       = []byte{AtypDomainName, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	addrDomainNameString = "example.com:443"
)

func TestAddrFromAndToAddrPort(t *testing.T) {
	addr := AddrFromAddrPort(addr4addrport)
	if !bytes.Equal(addr, addr4) {
		t.Fatalf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr = AddrFromAddrPort(addr4in6addrport)
	if !bytes.Equal(addr, addr4) {
		t.Fatalf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr = AddrFromAddrPort(addr6addrport)
	if !bytes.Equal(addr, addr6) {
		t.Fatalf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	addrPort, err := Addr(addr4).AddrPort(true)
	if err != nil {
		t.Fatal(err)
	}
	if addrPort != addr4addrport {
		t.Fatalf("Expected: %s\nGot: %s", addr4addrport, addrPort)
	}

	addrPort, err = Addr(addr6).AddrPort(true)
	if err != nil {
		t.Fatal(err)
	}
	if addrPort != addr6addrport {
		t.Fatalf("Expected: %s\nGot: %s", addr6addrport, addrPort)
	}
}

func TestAddrDomainNameToAddrPort(t *testing.T) {
	addrPort, err := Addr(addrDomainName).AddrPort(false)
	if err != nil {
		t.Fatal(err)
	}

	addr := addrPort.Addr()
	if !addr.Is4() && !addr.Is4In6() {
		t.Fatalf("preferIPv6: false returned IPv6: %s", addr)
	}

	port := addrPort.Port()
	if port != 443 {
		t.Fatalf("Expected port number: %d\nGot: %d", 443, port)
	}
}

func TestAddrParseAndToString(t *testing.T) {
	addr, err := ParseAddr(addr4str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Fatalf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr, err = ParseAddr(addr4in6str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Fatalf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr, err = ParseAddr(addr6str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr6) {
		t.Fatalf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	_, err = ParseAddr("abc123")
	if err == nil {
		t.Fatal("Parsing invalid address string should return error.")
	}

	address := Addr(addr4).String()
	if address != addr4str {
		t.Fatalf("Expected: %s\nGot: %s", addr4str, address)
	}

	address = Addr(addr4in6).String()
	if address != addr4str {
		t.Fatalf("Expected: %s\nGot: %s", addr4str, address)
	}

	address = Addr(addr6).String()
	if address != addr6str {
		t.Fatalf("Expected: %s\nGot: %s", addr6str, address)
	}

	address = Addr(addrDomainName).String()
	if address != addrDomainNameString {
		t.Fatalf("Expected: %s\nGot: %s", addrDomainNameString, address)
	}
}

func testAddrSplitAndFromReader(t *testing.T, addr []byte) {
	b := make([]byte, MaxAddrLen)
	n := copy(b, addr)
	_, err := rand.Read(b[n:])
	if err != nil {
		t.Fatal(err)
	}

	raddr, err := SplitAddr(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, raddr) {
		t.Fatalf("Expected: %v\nGot: %v", addr, raddr)
	}

	r := bytes.NewReader(b)
	raddr, err = AddrFromReader(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, raddr) {
		t.Fatalf("Expected: %v\nGot: %v", addr, raddr)
	}
}

func TestAddrSplitAndFromReader(t *testing.T) {
	testAddrSplitAndFromReader(t, addr4)
	testAddrSplitAndFromReader(t, addr4in6)
	testAddrSplitAndFromReader(t, addr6)
	testAddrSplitAndFromReader(t, addrDomainName)
}

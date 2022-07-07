package socks5

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
)

// Test IPv4 address.
var (
	addr4                = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4addr            = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addr4port     uint16 = 1080
	addr4addrport        = netip.AddrPortFrom(addr4addr, addr4port)
	addr4host            = "127.0.0.1"
	addr4str             = "127.0.0.1:1080"
)

// Test IPv4-mapped IPv6 address.
var (
	addr4in6                = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4in6addr            = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1})
	addr4in6port     uint16 = 1080
	addr4in6addrport        = netip.AddrPortFrom(addr4in6addr, addr4in6port)
	addr4in6host            = "::ffff:127.0.0.1"
	addr4in6str             = "[::ffff:127.0.0.1]:1080"
)

// Test IPv6 address.
var (
	addr6                = []byte{AtypIPv6, 0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e, 4, 56}
	addr6addr            = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addr6port     uint16 = 1080
	addr6addrport        = netip.AddrPortFrom(addr6addr, addr6port)
	addr6host            = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addr6str             = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

// Test domain name.
var (
	addrDomainName       = []byte{AtypDomainName, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	addrDomainNameHost   = "example.com"
	addrDomainNameString = "example.com:443"
)

func TestAddrIsDomainIP(t *testing.T) {
	if Addr(addr4).IsDomain() {
		t.Error("addr4.IsDomain() returned true.")
	}
	if !Addr(addr4).IsIPv4() {
		t.Error("addr4.IsIPv4() returned false.")
	}
	if Addr(addr4).IsIPv6() {
		t.Error("addr4.IsIPv6() returned true.")
	}

	if Addr(addr4in6).IsDomain() {
		t.Error("addr4in6.IsDomain() returned true.")
	}
	if !Addr(addr4in6).IsIPv4() {
		t.Error("addr4in6.IsIPv4() returned false.")
	}
	if Addr(addr4in6).IsIPv6() {
		t.Error("addr4in6.IsIPv6() returned true.")
	}

	if Addr(addr6).IsDomain() {
		t.Error("addr6.IsDomain() returned true.")
	}
	if Addr(addr6).IsIPv4() {
		t.Error("addr6.IsIPv4() returned true.")
	}
	if !Addr(addr6).IsIPv6() {
		t.Error("addr6.IsIPv6() returned false.")
	}

	if !Addr(addrDomainName).IsDomain() {
		t.Error("addrDomainName.IsDomain() returned false.")
	}
	if Addr(addrDomainName).IsIPv4() {
		t.Error("addrDomainName.IsIPv4() returned true.")
	}
	if Addr(addrDomainName).IsIPv6() {
		t.Error("addrDomainName.IsIPv6() returned true.")
	}
}

func TestAddrParseAndToHost(t *testing.T) {
	addr, err := ParseHostPort(addr4host, addr4port)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr, err = ParseHostPort(addr4in6host, addr4in6port)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4in6) {
		t.Errorf("Expected: %v\nGot: %v", addr4in6, []byte(addr))
	}

	addr, err = ParseHostPort(addr6host, addr6port)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr6) {
		t.Errorf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	host := Addr(addr4).Host()
	if host != addr4host {
		t.Errorf("Expected: %s\nGot: %s", addr4host, host)
	}

	host = Addr(addr4in6).Host()
	if host != addr4host {
		t.Errorf("Expected: %s\nGot: %s", addr4host, host)
	}

	host = Addr(addr6).Host()
	if host != addr6host {
		t.Errorf("Expected: %s\nGot: %s", addr6host, host)
	}

	host = Addr(addrDomainName).Host()
	if host != addrDomainNameHost {
		t.Errorf("Expected: %s\nGot: %s", addrDomainNameHost, host)
	}
}

func TestAddrToAddr(t *testing.T) {
	addr, err := Addr(addr4).Addr(true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != addr4addr {
		t.Errorf("Expected: %v\nGot: %v", addr4addr, addr)
	}

	addr, err = Addr(addr4in6).Addr(true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != addr4addr {
		t.Errorf("Expected: %v\nGot: %v", addr4addr, addr)
	}

	addr, err = Addr(addr6).Addr(true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != addr6addr {
		t.Errorf("Expected: %v\nGot: %v", addr6addr, addr)
	}

	addr, err = Addr(addrDomainName).Addr(false)
	if err != nil {
		t.Fatal(err)
	}
	if !addr.Is4() && !addr.Is4In6() {
		t.Errorf("preferIPv6: false returned IPv6: %s", addr)
	}

	addr, err = Addr(addrDomainName).Addr(true)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Is4() || addr.Is4In6() {
		t.Errorf("preferIPv6: true returned IPv4: %s", addr)
	}
}

func TestAddrToPort(t *testing.T) {
	port := Addr(addr4).Port()
	eport := addr4addrport.Port()
	if port != eport {
		t.Errorf("Expected: %d\nGot: %d", eport, port)
	}

	port = Addr(addr6).Port()
	eport = addr6addrport.Port()
	if port != eport {
		t.Errorf("Expected: %d\nGot: %d", eport, port)
	}

	port = Addr(addrDomainName).Port()
	eport = 443
	if port != eport {
		t.Errorf("Expected: %d\nGot: %d", eport, port)
	}
}

func TestAddrFromAndToAddrPort(t *testing.T) {
	addr := AddrFromAddrPort(addr4addrport)
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr = AddrFromAddrPort(addr4in6addrport)
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr = AddrFromAddrPort(addr6addrport)
	if !bytes.Equal(addr, addr6) {
		t.Errorf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	addrPort, err := Addr(addr4).AddrPort(true)
	if err != nil {
		t.Fatal(err)
	}
	if addrPort != addr4addrport {
		t.Errorf("Expected: %s\nGot: %s", addr4addrport, addrPort)
	}

	addrPort, err = Addr(addr6).AddrPort(true)
	if err != nil {
		t.Fatal(err)
	}
	if addrPort != addr6addrport {
		t.Errorf("Expected: %s\nGot: %s", addr6addrport, addrPort)
	}
}

func TestAddrDomainNameToAddrPort(t *testing.T) {
	addrPort, err := Addr(addrDomainName).AddrPort(false)
	if err != nil {
		t.Fatal(err)
	}

	addr := addrPort.Addr()
	if !addr.Is4() && !addr.Is4In6() {
		t.Errorf("preferIPv6: false returned IPv6: %s", addr)
	}

	port := addrPort.Port()
	if port != 443 {
		t.Errorf("Expected port number: %d\nGot: %d", 443, port)
	}

	addrPort, err = Addr(addrDomainName).AddrPort(true)
	if err != nil {
		t.Fatal(err)
	}

	addr = addrPort.Addr()
	if addr.Is4() || addr.Is4In6() {
		t.Errorf("preferIPv6: true returned IPv4: %s", addr)
	}

	port = addrPort.Port()
	if port != 443 {
		t.Errorf("Expected port number: %d\nGot: %d", 443, port)
	}
}

func TestAddrParseAndToString(t *testing.T) {
	addr, err := ParseAddr(addr4str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr, err = ParseAddr(addr4in6str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	addr, err = ParseAddr(addr6str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr6) {
		t.Errorf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	_, err = ParseAddr("abc123")
	if err == nil {
		t.Fatal("Parsing invalid address string should return error.")
	}

	address := Addr(addr4).String()
	if address != addr4str {
		t.Errorf("Expected: %s\nGot: %s", addr4str, address)
	}

	address = Addr(addr4in6).String()
	if address != addr4str {
		t.Errorf("Expected: %s\nGot: %s", addr4str, address)
	}

	address = Addr(addr6).String()
	if address != addr6str {
		t.Errorf("Expected: %s\nGot: %s", addr6str, address)
	}

	address = Addr(addrDomainName).String()
	if address != addrDomainNameString {
		t.Errorf("Expected: %s\nGot: %s", addrDomainNameString, address)
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
		t.Errorf("Expected: %v\nGot: %v", addr, []byte(raddr))
	}

	r := bytes.NewReader(b)
	raddr, err = AddrFromReader(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, raddr) {
		t.Errorf("Expected: %v\nGot: %v", addr, []byte(raddr))
	}
}

func TestAddrSplitAndFromReader(t *testing.T) {
	testAddrSplitAndFromReader(t, addr4)
	testAddrSplitAndFromReader(t, addr4in6)
	testAddrSplitAndFromReader(t, addr6)
	testAddrSplitAndFromReader(t, addrDomainName)
}

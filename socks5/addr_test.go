package socks5

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
)

// Test IPv4 address.
var (
	addr4                = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4addr            = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addr4port     uint16 = 1080
	addr4addrport        = netip.AddrPortFrom(addr4addr, addr4port)
	addr4connaddr        = conn.AddrFromIPPort(addr4addrport)
	addr4host            = "127.0.0.1"
	addr4str             = "127.0.0.1:1080"
)

// Test IPv4-mapped IPv6 address.
var (
	addr4in6                = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4in6addr            = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1})
	addr4in6port     uint16 = 1080
	addr4in6addrport        = netip.AddrPortFrom(addr4in6addr, addr4in6port)
	addr4in6connaddr        = conn.AddrFromIPPort(addr4in6addrport)
	addr4in6host            = "::ffff:127.0.0.1"
	addr4in6str             = "[::ffff:127.0.0.1]:1080"
)

// Test IPv6 address.
var (
	addr6                = []byte{AtypIPv6, 0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e, 4, 56}
	addr6addr            = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addr6port     uint16 = 1080
	addr6addrport        = netip.AddrPortFrom(addr6addr, addr6port)
	addr6connaddr        = conn.AddrFromIPPort(addr6addrport)
	addr6host            = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addr6str             = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

// Test domain name.
var (
	addrDomain                = []byte{AtypDomainName, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	addrDomainHost            = "example.com"
	addrDomainPort     uint16 = 443
	addrDomainConnAddr        = conn.MustAddrFromDomainPort(addrDomainHost, addrDomainPort)
	addrDomainString          = "example.com:443"
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

	if !Addr(addrDomain).IsDomain() {
		t.Error("addrDomainName.IsDomain() returned false.")
	}
	if Addr(addrDomain).IsIPv4() {
		t.Error("addrDomainName.IsIPv4() returned true.")
	}
	if Addr(addrDomain).IsIPv6() {
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

	host = Addr(addrDomain).Host()
	if host != addrDomainHost {
		t.Errorf("Expected: %s\nGot: %s", addrDomainHost, host)
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

	addr, err = Addr(addrDomain).Addr(false)
	if err != nil {
		t.Fatal(err)
	}
	if !addr.Is4() && !addr.Is4In6() {
		t.Errorf("preferIPv6: false returned IPv6: %s", addr)
	}

	addr, err = Addr(addrDomain).Addr(true)
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

	port = Addr(addrDomain).Port()
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
	addrPort, err := Addr(addrDomain).AddrPort(false)
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

	addrPort, err = Addr(addrDomain).AddrPort(true)
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

	addr, err = ParseAddr(addrDomainString)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addrDomain) {
		t.Errorf("Expected: %v\nGot: %v", addrDomain, []byte(addr))
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

	address = Addr(addrDomain).String()
	if address != addrDomainString {
		t.Errorf("Expected: %s\nGot: %s", addrDomainString, address)
	}
}

func TestAddrUnmarshalAndMarshalText(t *testing.T) {
	var addr Addr

	err := addr.UnmarshalText([]byte(addr4str))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	err = addr.UnmarshalText([]byte(addr4in6str))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr4) {
		t.Errorf("Expected: %v\nGot: %v", addr4, []byte(addr))
	}

	err = addr.UnmarshalText([]byte(addr6str))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addr6) {
		t.Errorf("Expected: %v\nGot: %v", addr6, []byte(addr))
	}

	err = addr.UnmarshalText([]byte(addrDomainString))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, addrDomain) {
		t.Errorf("Expected: %v\nGot: %v", addrDomain, []byte(addr))
	}

	err = addr.UnmarshalText([]byte("abc123"))
	if err == nil {
		t.Fatal("Parsing invalid address string should return error.")
	}

	address, err := Addr(addr4).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(address) != addr4str {
		t.Errorf("Expected: %s\nGot: %s", addr4str, address)
	}

	address, err = Addr(addr4in6).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(address) != addr4str {
		t.Errorf("Expected: %s\nGot: %s", addr4str, address)
	}

	address, err = Addr(addr6).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(address) != addr6str {
		t.Errorf("Expected: %s\nGot: %s", addr6str, address)
	}

	address, err = Addr(addrDomain).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(address) != addrDomainString {
		t.Errorf("Expected: %s\nGot: %s", addrDomainString, address)
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
	testAddrSplitAndFromReader(t, addrDomain)
}

func testAddrPortFromSlice(t *testing.T, sa []byte, expectedAddrPort netip.AddrPort, expectedN int, expectedErr error) {
	b := make([]byte, 512)
	n := copy(b, sa)
	_, err := rand.Read(b[n:])
	if err != nil {
		t.Fatal(err)
	}
	expectedTail := make([]byte, 512-n)
	copy(expectedTail, b[n:])

	addrPort, n, err := AddrPortFromSlice(b)
	if err != expectedErr {
		t.Errorf("AddrPortFromSlice(b) returned error %s, expected error %s", err, expectedErr)
	}
	if n != expectedN {
		t.Errorf("AddrPortFromSlice(b) returned n=%d, expected n=%d.", n, expectedN)
	}
	if addrPort != expectedAddrPort {
		t.Errorf("AddrPortFromSlice(b) returned %s, expected %s.", addrPort, expectedAddrPort)
	}
	if !bytes.Equal(b[len(sa):], expectedTail) {
		t.Error("AddrPortFromSlice(b) modified non-address bytes.")
	}
}

func TestAddrPortFromSlice(t *testing.T) {
	testAddrPortFromSlice(t, addr4, addr4addrport, len(addr4), nil)
	testAddrPortFromSlice(t, addr4in6, addr4addrport, len(addr4in6), nil)
	testAddrPortFromSlice(t, addr6, addr6addrport, len(addr6), nil)
	testAddrPortFromSlice(t, addrDomain, netip.AddrPort{}, 0, errDomain)
}

func testAddrFromSliceAndReader(t *testing.T, sa []byte, expectedAddr conn.Addr) {
	b := make([]byte, 512)
	n := copy(b, sa)
	_, err := rand.Read(b[n:])
	if err != nil {
		t.Fatal(err)
	}
	expectedTail := make([]byte, 512-n)
	copy(expectedTail, b[n:])

	addr, n, err := ConnAddrFromSlice(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(sa) {
		t.Errorf("ConnAddrFromSlice(b) returned n=%d, expected n=%d.", n, len(sa))
	}
	if addr != expectedAddr {
		t.Errorf("ConnAddrFromSlice(b) returned %s, expected %s.", addr, expectedAddr)
	}
	if !bytes.Equal(b[n:], expectedTail) {
		t.Error("ConnAddrFromSlice(b) modified non-address bytes.")
	}

	r := bytes.NewReader(b)
	addr, err = ConnAddrFromReader(r)
	if err != nil {
		t.Fatal(err)
	}
	if addr != expectedAddr {
		t.Errorf("ConnAddrFromReader(r) returned %s, expected %s.", addr, expectedAddr)
	}
	tail, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail, expectedTail) {
		t.Error("ConnAddrFromReader(r) read more bytes than expected.")
	}
}

func TestAddrFromSliceAndReader(t *testing.T) {
	testAddrFromSliceAndReader(t, addr4, addr4connaddr)
	testAddrFromSliceAndReader(t, addr4in6, addr4connaddr)
	testAddrFromSliceAndReader(t, addr6, addr6connaddr)
	testAddrFromSliceAndReader(t, addrDomain, addrDomainConnAddr)
}

func testAddrFromSliceWithDomainCache(t *testing.T, sa []byte, cachedDomain string, expectedAddr conn.Addr) string {
	b := make([]byte, 512)
	n := copy(b, sa)
	_, err := rand.Read(b[n:])
	if err != nil {
		t.Fatal(err)
	}
	expectedTail := make([]byte, 512-n)
	copy(expectedTail, b[n:])

	addr, n, cachedDomain, err := ConnAddrFromSliceWithDomainCache(b, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(sa) {
		t.Errorf("ConnAddrFromSlice(b) returned n=%d, expected n=%d.", n, len(sa))
	}
	if addr != expectedAddr {
		t.Errorf("ConnAddrFromSlice(b) returned %s, expected %s.", addr, expectedAddr)
	}
	if !bytes.Equal(b[n:], expectedTail) {
		t.Error("ConnAddrFromSlice(b) modified non-address bytes.")
	}
	return cachedDomain
}

func TestAddrFromSliceWithDomainCache(t *testing.T) {
	const s = "🌐"
	cachedDomain := s

	cachedDomain = testAddrFromSliceWithDomainCache(t, addr4, cachedDomain, addr4connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr4) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testAddrFromSliceWithDomainCache(t, addr4in6, cachedDomain, addr4connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr4in6) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testAddrFromSliceWithDomainCache(t, addr6, cachedDomain, addr6connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr6) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testAddrFromSliceWithDomainCache(t, addrDomain, cachedDomain, addrDomainConnAddr)
	if cachedDomain != addrDomainHost {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addrDomain) modified cachedDomain to %s, expected %s.", cachedDomain, addrDomainHost)
	}
}

func testAppendAddrFromConnAddr(t *testing.T, addr conn.Addr, expectedSA []byte) {
	head := make([]byte, 64)
	_, err := rand.Read(head)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 0, 512)
	b = append(b, head...)

	b = AppendAddrFromConnAddr(b, addr)
	if !bytes.Equal(b[:64], head) {
		t.Error("Random head mismatch.")
	}
	if !bytes.Equal(b[64:], expectedSA) {
		t.Errorf("Appended SOCKS address is %v, expected %v.", b[64:], expectedSA)
	}
}

func TestAppendAddrFromConnAddr(t *testing.T) {
	testAppendAddrFromConnAddr(t, addr4connaddr, addr4)
	testAppendAddrFromConnAddr(t, addr4in6connaddr, addr4in6)
	testAppendAddrFromConnAddr(t, addr6connaddr, addr6)
	testAppendAddrFromConnAddr(t, addrDomainConnAddr, addrDomain)
}

func testLengthOfAndWriteAddrFromConnAddr(t *testing.T, addr conn.Addr, expectedSA []byte) {
	addrLen := LengthOfAddrFromConnAddr(addr)
	if addrLen != len(expectedSA) {
		t.Errorf("LengthOfAddrFromConnAddr(addr) returned %d, expected %d.", addrLen, len(expectedSA))
	}

	b := make([]byte, 512)
	_, err := rand.Read(b[addrLen:])
	if err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, 512-addrLen)
	copy(tail, b[addrLen:])

	n := WriteAddrFromConnAddr(b, addr)
	if n != len(expectedSA) {
		t.Errorf("WriteAddrFromConnAddr(b, addr) returned n=%d, expected n=%d.", n, len(expectedSA))
	}
	if !bytes.Equal(b[:len(expectedSA)], expectedSA) {
		t.Errorf("WriteAddrFromConnAddr(b, addr) wrote %v, expected %v.", b[:len(expectedSA)], expectedSA)
	}
	if !bytes.Equal(b[len(expectedSA):], tail) {
		t.Error("WriteAddrFromConnAddr(b, addr) modified non-address bytes.")
	}
}

func TestLengthOfAndWriteAddrFromConnAddr(t *testing.T) {
	testLengthOfAndWriteAddrFromConnAddr(t, addr4connaddr, addr4)
	testLengthOfAndWriteAddrFromConnAddr(t, addr4in6connaddr, addr4in6)
	testLengthOfAndWriteAddrFromConnAddr(t, addr6connaddr, addr6)
	testLengthOfAndWriteAddrFromConnAddr(t, addrDomainConnAddr, addrDomain)
}

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
)

// Test IPv4-mapped IPv6 address.
var (
	addr4in6                = []byte{AtypIPv4, 127, 0, 0, 1, 4, 56}
	addr4in6addr            = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1})
	addr4in6port     uint16 = 1080
	addr4in6addrport        = netip.AddrPortFrom(addr4in6addr, addr4in6port)
	addr4in6connaddr        = conn.AddrFromIPPort(addr4in6addrport)
)

// Test IPv6 address.
var (
	addr6                = []byte{AtypIPv6, 0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e, 4, 56}
	addr6addr            = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addr6port     uint16 = 1080
	addr6addrport        = netip.AddrPortFrom(addr6addr, addr6port)
	addr6connaddr        = conn.AddrFromIPPort(addr6addrport)
)

// Test domain name.
var (
	addrDomain                = []byte{AtypDomainName, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	addrDomainHost            = "example.com"
	addrDomainPort     uint16 = 443
	addrDomainConnAddr        = conn.MustAddrFromDomainPort(addrDomainHost, addrDomainPort)
)

func testAddrFromReader(t *testing.T, addr []byte) {
	b := make([]byte, 512)
	n := copy(b, addr)
	_, err := rand.Read(b[n:])
	if err != nil {
		t.Fatal(err)
	}
	expectedTail := make([]byte, 512-n)
	copy(expectedTail, b[n:])

	r := bytes.NewReader(b)
	raddr, err := AddrFromReader(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(addr, raddr) {
		t.Errorf("Expected: %v\nGot: %v", addr, []byte(raddr))
	}
	tail, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail, expectedTail) {
		t.Error("AddrFromReader(r) read more bytes than expected.")
	}
}

func TestAddrFromReader(t *testing.T) {
	testAddrFromReader(t, addr4)
	testAddrFromReader(t, addr4in6)
	testAddrFromReader(t, addr6)
	testAddrFromReader(t, addrDomain)
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

func testConnAddrFromSliceAndReader(t *testing.T, sa []byte, expectedAddr conn.Addr) {
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
	if !addr.Equals(expectedAddr) {
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
	if !addr.Equals(expectedAddr) {
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

func TestConnAddrFromSliceAndReader(t *testing.T) {
	testConnAddrFromSliceAndReader(t, addr4, addr4connaddr)
	testConnAddrFromSliceAndReader(t, addr4in6, addr4connaddr)
	testConnAddrFromSliceAndReader(t, addr6, addr6connaddr)
	testConnAddrFromSliceAndReader(t, addrDomain, addrDomainConnAddr)
}

func testConnAddrFromSliceWithDomainCache(t *testing.T, sa []byte, cachedDomain string, expectedAddr conn.Addr) string {
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
	if !addr.Equals(expectedAddr) {
		t.Errorf("ConnAddrFromSlice(b) returned %s, expected %s.", addr, expectedAddr)
	}
	if !bytes.Equal(b[n:], expectedTail) {
		t.Error("ConnAddrFromSlice(b) modified non-address bytes.")
	}
	return cachedDomain
}

func TestConnAddrFromSliceWithDomainCache(t *testing.T) {
	const s = "🌐"
	cachedDomain := s

	cachedDomain = testConnAddrFromSliceWithDomainCache(t, addr4, cachedDomain, addr4connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr4) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testConnAddrFromSliceWithDomainCache(t, addr4in6, cachedDomain, addr4connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr4in6) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testConnAddrFromSliceWithDomainCache(t, addr6, cachedDomain, addr6connaddr)
	if cachedDomain != s {
		t.Errorf("ConnAddrFromSliceWithDomainCache(addr6) modified cachedDomain to %s.", cachedDomain)
	}

	cachedDomain = testConnAddrFromSliceWithDomainCache(t, addrDomain, cachedDomain, addrDomainConnAddr)
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

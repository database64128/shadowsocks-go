package socks5

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
)

// Test zero value address.

var (
	addrZero         = IPv4UnspecifiedAddr
	addrZeroConnAddr conn.Addr
)

// Test IPv4 address.

const addr4port uint16 = 1080

var (
	addr4 = [IPv4AddrLen]byte{
		AtypIPv4,
		127, 0, 0, 1,
		byte(addr4port >> 8), byte(addr4port & 0xff),
	}
	addr4addr     = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addr4addrport = netip.AddrPortFrom(addr4addr, addr4port)
	addr4connaddr = conn.AddrFromIPPort(addr4addrport)
)

// Test IPv4-mapped IPv6 address.

const addr4in6port uint16 = 1080

var (
	addr4in6 = [IPv4AddrLen]byte{
		AtypIPv4,
		127, 0, 0, 1,
		byte(addr4in6port >> 8), byte(addr4in6port & 0xff),
	}
	addr4in6addr     = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1})
	addr4in6addrport = netip.AddrPortFrom(addr4in6addr, addr4in6port)
	addr4in6connaddr = conn.AddrFromIPPort(addr4in6addrport)
)

// Test IPv6 address.

const addr6port uint16 = 1080

var (
	addr6 = [IPv6AddrLen]byte{
		AtypIPv6,
		0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e,
		byte(addr6port >> 8), byte(addr6port & 0xff),
	}
	addr6addr     = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addr6addrport = netip.AddrPortFrom(addr6addr, addr6port)
	addr6connaddr = conn.AddrFromIPPort(addr6addrport)
)

// Test domain name.

const (
	addrDomainHost        = "example.com"
	addrDomainPort uint16 = 443
)

var (
	addrDomain = [1 + 1 + len(addrDomainHost) + 2]byte{
		AtypDomainName,
		byte(len(addrDomainHost)),
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		byte(addrDomainPort >> 8), byte(addrDomainPort & 0xff),
	}
	addrDomainConnAddr = conn.MustAddrFromDomainPort(addrDomainHost, addrDomainPort)
)

func testAddrFromReader(t *testing.T, addr []byte) {
	b := make([]byte, 512)
	n := copy(b, addr)
	rand.Read(b[n:])
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
	testAddrFromReader(t, addr4[:])
	testAddrFromReader(t, addr4in6[:])
	testAddrFromReader(t, addr6[:])
	testAddrFromReader(t, addrDomain[:])
}

func testAddrPortFromSlice(t *testing.T, sa []byte, expectedAddrPort netip.AddrPort, expectedN int, expectedErr error) {
	b := make([]byte, 512)
	n := copy(b, sa)
	rand.Read(b[n:])
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
	testAddrPortFromSlice(t, addr4[:], addr4addrport, len(addr4), nil)
	testAddrPortFromSlice(t, addr4in6[:], addr4addrport, len(addr4in6), nil)
	testAddrPortFromSlice(t, addr6[:], addr6addrport, len(addr6), nil)
	testAddrPortFromSlice(t, addrDomain[:], netip.AddrPort{}, 0, errDomain)
}

func testConnAddrFromSliceAndReader(t *testing.T, sa []byte, expectedAddr conn.Addr) {
	b := make([]byte, 512)
	n := copy(b, sa)
	rand.Read(b[n:])
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
	testConnAddrFromSliceAndReader(t, addr4[:], addr4connaddr)
	testConnAddrFromSliceAndReader(t, addr4in6[:], addr4connaddr)
	testConnAddrFromSliceAndReader(t, addr6[:], addr6connaddr)
	testConnAddrFromSliceAndReader(t, addrDomain[:], addrDomainConnAddr)
}

func testConnAddrFromSliceWithDomainCache(t *testing.T, b, sa []byte, dc *DomainCache, expectedAddr conn.Addr) {
	n := copy(b, sa)
	tail := b[n:]
	rand.Read(tail)
	expectedTail := make([]byte, 0, 512)
	expectedTail = append(expectedTail, tail...)

	addr, n, err := dc.ConnAddrFromSlice(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(sa) {
		t.Errorf("dc.ConnAddrFromSlice(%x) returned n=%d, expected n=%d", b, n, len(sa))
	}
	if !addr.Equals(expectedAddr) {
		t.Errorf("dc.ConnAddrFromSlice(%x) returned %s, expected %s", b, addr, expectedAddr)
	}
	if !bytes.Equal(b[n:], expectedTail) {
		t.Errorf("dc.ConnAddrFromSlice(%x) modified non-address bytes", b)
	}
}

func TestConnAddrFromSliceWithDomainCache(t *testing.T) {
	var dc DomainCache
	b := make([]byte, 512)

	if n := testing.AllocsPerRun(10, func() {
		testConnAddrFromSliceWithDomainCache(t, b, addr4[:], &dc, addr4connaddr)
		testConnAddrFromSliceWithDomainCache(t, b, addr4in6[:], &dc, addr4connaddr)
		testConnAddrFromSliceWithDomainCache(t, b, addr6[:], &dc, addr6connaddr)
		testConnAddrFromSliceWithDomainCache(t, b, addrDomain[:], &dc, addrDomainConnAddr)
	}); n > 0 {
		t.Errorf("AllocsPerRun(10, ...) = %f, want 0", n)
	}

	const addrDomain2Host = "www.google.com"
	addrDomain2 := [1 + 1 + len(addrDomain2Host) + 2]byte{
		AtypDomainName,
		byte(len(addrDomain2Host)),
		'w', 'w', 'w', '.', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm',
		byte(addrDomainPort >> 8), byte(addrDomainPort & 0xff),
	}
	addrDomain2ConnAddr := conn.MustAddrFromDomainPort(addrDomain2Host, addrDomainPort)

	if n := testing.AllocsPerRun(10, func() {
		testConnAddrFromSliceWithDomainCache(t, b, addrDomain2[:], &dc, addrDomain2ConnAddr)
	}); n > 0 {
		t.Errorf("AllocsPerRun(10, ...) = %f, want 0", n)
	}
}

func testAppendAddrFromConnAddr(t *testing.T, addr conn.Addr, expectedSA []byte) {
	head := make([]byte, 64)
	rand.Read(head)

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
	testAppendAddrFromConnAddr(t, addrZeroConnAddr, addrZero[:])
	testAppendAddrFromConnAddr(t, addr4connaddr, addr4[:])
	testAppendAddrFromConnAddr(t, addr4in6connaddr, addr4in6[:])
	testAppendAddrFromConnAddr(t, addr6connaddr, addr6[:])
	testAppendAddrFromConnAddr(t, addrDomainConnAddr, addrDomain[:])
}

func testLengthOfAndWriteAddrFromConnAddr(t *testing.T, addr conn.Addr, expectedSA []byte) {
	addrLen := LengthOfAddrFromConnAddr(addr)
	if addrLen != len(expectedSA) {
		t.Errorf("LengthOfAddrFromConnAddr(addr) returned %d, expected %d.", addrLen, len(expectedSA))
	}

	b := make([]byte, 512)
	rand.Read(b[addrLen:])
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
	testLengthOfAndWriteAddrFromConnAddr(t, addrZeroConnAddr, addrZero[:])
	testLengthOfAndWriteAddrFromConnAddr(t, addr4connaddr, addr4[:])
	testLengthOfAndWriteAddrFromConnAddr(t, addr4in6connaddr, addr4in6[:])
	testLengthOfAndWriteAddrFromConnAddr(t, addr6connaddr, addr6[:])
	testLengthOfAndWriteAddrFromConnAddr(t, addrDomainConnAddr, addrDomain[:])
}

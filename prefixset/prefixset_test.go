package prefixset

import (
	"net/netip"
	"testing"

	"go4.org/netipx"
)

const testPrefixSetText = `# Private prefixes.
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/3
::1/128
fc00::/7
fe80::/10
ff00::/8
`

func testContains(t *testing.T, s *netipx.IPSet, addr netip.Addr, expectedResult bool) {
	if s.Contains(addr) != expectedResult {
		t.Errorf("%s should return %v", addr, expectedResult)
	}
}

func testPrefixSet(t *testing.T, s *netipx.IPSet) {
	testContains(t, s, netip.IPv4Unspecified(), true)
	testContains(t, s, netip.AddrFrom4([4]byte{10, 0, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{100, 64, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{127, 0, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{169, 254, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{172, 16, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{192, 0, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{192, 0, 2, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{192, 88, 99, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{192, 168, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{198, 18, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{198, 51, 100, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{203, 0, 113, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{224, 0, 0, 1}), true)
	testContains(t, s, netip.AddrFrom4([4]byte{1, 1, 1, 1}), false)
	testContains(t, s, netip.AddrFrom4([4]byte{8, 8, 8, 8}), false)
	testContains(t, s, netip.IPv6Loopback(), true)
	testContains(t, s, netip.AddrFrom16([16]byte{0: 0xfc, 15: 1}), true)
	testContains(t, s, netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 15: 1}), true)
	testContains(t, s, netip.AddrFrom16([16]byte{0: 0xff, 15: 1}), true)
	testContains(t, s, netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e}), false)
	testContains(t, s, netip.IPv6Unspecified(), false)
}

func TestPrefixSet(t *testing.T) {
	s, err := IPSetFromText(testPrefixSetText)
	if err != nil {
		t.Fatal(err)
	}

	testPrefixSet(t, s)

	text := IPSetToText(s)
	if string(text) != testPrefixSetText[20:] {
		t.Errorf("IPSetToText(s) returned %s", text)
	}
}

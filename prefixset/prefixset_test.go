package prefixset

import (
	"net/netip"
	"slices"
	"testing"
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

var sortedTestPrefixes = [...]netip.Prefix{
	netip.PrefixFrom(netip.IPv4Unspecified(), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, 0, 0}), 16),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, 0, 0}), 12),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 88, 99, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 16),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{224, 0, 0, 0}), 3),
	netip.PrefixFrom(netip.IPv6Loopback(), 128),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfc}), 7),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfe, 0x80}), 10),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0xff}), 8),
}

var testPrefixSetContainsCases = [...]struct {
	addr netip.Addr
	want bool
}{
	{netip.IPv4Unspecified(), true},
	{netip.AddrFrom4([4]byte{10, 0, 0, 1}), true},
	{netip.AddrFrom4([4]byte{100, 64, 0, 1}), true},
	{netip.AddrFrom4([4]byte{127, 0, 0, 1}), true},
	{netip.AddrFrom4([4]byte{169, 254, 0, 1}), true},
	{netip.AddrFrom4([4]byte{172, 16, 0, 1}), true},
	{netip.AddrFrom4([4]byte{192, 0, 0, 1}), true},
	{netip.AddrFrom4([4]byte{192, 0, 2, 1}), true},
	{netip.AddrFrom4([4]byte{192, 88, 99, 1}), true},
	{netip.AddrFrom4([4]byte{192, 168, 0, 1}), true},
	{netip.AddrFrom4([4]byte{198, 18, 0, 1}), true},
	{netip.AddrFrom4([4]byte{198, 51, 100, 1}), true},
	{netip.AddrFrom4([4]byte{203, 0, 113, 1}), true},
	{netip.AddrFrom4([4]byte{224, 0, 0, 1}), true},
	{netip.AddrFrom4([4]byte{1, 1, 1, 1}), false},
	{netip.AddrFrom4([4]byte{8, 8, 8, 8}), false},
	{netip.IPv6Loopback(), true},
	{netip.AddrFrom16([16]byte{0: 0xfc, 15: 1}), true},
	{netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 15: 1}), true},
	{netip.AddrFrom16([16]byte{0: 0xff, 15: 1}), true},
	{netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e}), false},
	{netip.IPv6Unspecified(), false},
}

func TestPrefixSet(t *testing.T) {
	s, err := PrefixSetFromText(testPrefixSetText)
	if err != nil {
		t.Fatalf("PrefixSetFromText(testPrefixSetText) failed: %v", err)
	}

	for _, cc := range testPrefixSetContainsCases {
		if got := s.Contains(cc.addr); got != cc.want {
			t.Errorf("s.Contains(%q) = %v, want %v", cc.addr, got, cc.want)
		}
	}

	got := make([]netip.Prefix, 0, s.Size())
	for prefix := range s.AllSorted() {
		got = append(got, prefix)
	}
	if !slices.Equal(got, sortedTestPrefixes[:]) {
		t.Errorf("s.AllSorted() = %v, want %v", got, sortedTestPrefixes[:])
	}
}

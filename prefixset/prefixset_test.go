package prefixset

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gaissmai/bart"
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
::/128
::1/128
fc00::/7
fe80::/10
ff00::/8
`

var testPrefixSet bart.Lite

func init() {
	for _, prefix := range sortedTestPrefixes {
		testPrefixSet.Insert(prefix)
	}
}

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
	netip.PrefixFrom(netip.IPv6Unspecified(), 128),
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
	{netip.IPv6Unspecified(), true},
}

func TestPrefixSetText(t *testing.T) {
	s, err := PrefixSetFromText(testPrefixSetText)
	if err != nil {
		t.Fatalf("PrefixSetFromText(testPrefixSetText) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equals(&testPrefixSet) = false, want true")
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

func TestPrefixSetBinary(t *testing.T) {
	length := 24 + len(sortedTestPrefixes)
	for _, prefix := range sortedTestPrefixes {
		length += (prefix.Bits() + 7) / 8
	}

	bw := bytes.NewBuffer(make([]byte, 0, length))
	if err := MarshalWriteBinary(bw, &testPrefixSet); err != nil {
		t.Fatalf("MarshalWriteBinary(bw, &testPrefixSet) failed: %v", err)
	}
	if got := bw.Len(); got != length {
		t.Errorf("bw.Len() = %d, want %d", got, length)
	}

	t.Logf("bw.Bytes() = %#v", bw.Bytes())

	var s bart.Lite
	if err := UnmarshalReadBinary(bw, &s); err != nil {
		t.Fatalf("UnmarshalReadBinary(bw, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equals(&testPrefixSet) = false, want true")
	}
}

func TestConfigLoadPrefixSetError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken-prefixset.txt")
	if err := os.WriteFile(path, []byte("I'm not a prefix set!\n"), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", path, err)
	}

	cfg := Config{
		Name: "broken",
		Path: path,
	}
	_, err := cfg.LoadPrefixSet()
	if err == nil {
		t.Fatal("cfg.LoadPrefixSet() did not return an error")
	}

	// Dereference the error string to make sure it does not cause a panic.
	t.Logf("cfg.LoadPrefixSet() returned error: %v", err)
}

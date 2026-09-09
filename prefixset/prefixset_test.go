package prefixset_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/database64128/shadowsocks-go/prefixset"
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

func TestPrefixSet(t *testing.T) {
	for _, cc := range testPrefixSetContainsCases {
		if got := testPrefixSet.Contains(cc.addr); got != cc.want {
			t.Errorf("testPrefixSet.Contains(%q) = %v, want %v", cc.addr, got, cc.want)
		}
	}

	got := make([]netip.Prefix, 0, testPrefixSet.Size())
	for prefix := range testPrefixSet.AllSorted() {
		got = append(got, prefix)
	}
	if !slices.Equal(got, sortedTestPrefixes[:]) {
		t.Errorf("testPrefixSet.AllSorted() = %v, want %v", got, sortedTestPrefixes[:])
	}
}

func TestPrefixSetMarshalText(t *testing.T) {
	text := prefixset.MarshalText(&testPrefixSet)
	var s bart.Lite
	if err := prefixset.UnmarshalText(string(text), &s); err != nil {
		t.Fatalf("UnmarshalText(text, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equal(&testPrefixSet) = false, want true")
	}
}

func TestPrefixSetUnmarshalText(t *testing.T) {
	var s bart.Lite
	if err := prefixset.UnmarshalText(testPrefixSetText, &s); err != nil {
		t.Fatalf("UnmarshalText(testPrefixSetText, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equal(&testPrefixSet) = false, want true")
	}
}

func TestPrefixSetMarshalWriteText(t *testing.T) {
	for _, c := range [...]struct {
		name string
		buf  interface {
			io.Writer
			fmt.Stringer
		}
	}{
		{"bytes.Buffer", &bytes.Buffer{}}, // has Available{,Buffer} methods
		{"strings.Builder", &strings.Builder{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := prefixset.MarshalWriteText(c.buf, &testPrefixSet); err != nil {
				t.Fatalf("MarshalWriteText(c.buf, &testPrefixSet) failed: %v", err)
			}
			var s bart.Lite
			if err := prefixset.UnmarshalText(c.buf.String(), &s); err != nil {
				t.Fatalf("UnmarshalText(c.buf.String(), &s) failed: %v", err)
			}
			if !s.Equal(&testPrefixSet) {
				t.Errorf("s.Equal(&testPrefixSet) = false, want true")
			}
		})
	}
}

func TestPrefixSetUnmarshalReadText(t *testing.T) {
	var s bart.Lite
	br := bufio.NewReader(strings.NewReader(testPrefixSetText))
	if err := prefixset.UnmarshalReadText(br, &s); err != nil {
		t.Fatalf("UnmarshalReadText(br, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equal(&testPrefixSet) = false, want true")
	}
}

func TestPrefixSetBinary(t *testing.T) {
	length := 24 + len(sortedTestPrefixes)
	for _, prefix := range sortedTestPrefixes {
		length += (prefix.Bits() + 7) / 8
	}

	bw := bytes.NewBuffer(make([]byte, 0, length))
	if err := prefixset.MarshalWriteBinary(bw, &testPrefixSet); err != nil {
		t.Fatalf("MarshalWriteBinary(bw, &testPrefixSet) failed: %v", err)
	}
	if got := bw.Len(); got != length {
		t.Errorf("bw.Len() = %d, want %d", got, length)
	}

	t.Logf("bw.Bytes() = %#v", bw.Bytes())

	var s bart.Lite
	if err := prefixset.UnmarshalReadBinary(bw, &s); err != nil {
		t.Fatalf("UnmarshalReadBinary(bw, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equal(&testPrefixSet) = false, want true")
	}
}

func TestPrefixSetMarshalWriteBinaryNonByteWriter(t *testing.T) {
	type readWriter struct {
		io.ReadWriter
	}
	rw := readWriter{&bytes.Buffer{}}
	if err := prefixset.MarshalWriteBinary(rw, &testPrefixSet); err != nil {
		t.Fatalf("MarshalWriteBinary(rw, &testPrefixSet) failed: %v", err)
	}

	var s bart.Lite
	if err := prefixset.UnmarshalReadBinary(rw, &s); err != nil {
		t.Fatalf("UnmarshalReadBinary(rw, &s) failed: %v", err)
	}
	if !s.Equal(&testPrefixSet) {
		t.Errorf("s.Equal(&testPrefixSet) = false, want true")
	}
}

func TestPrefixSetUnmarshalReadBinaryError(t *testing.T) {
	var buf bytes.Buffer
	if err := prefixset.MarshalWriteBinary(&buf, &testPrefixSet); err != nil {
		t.Fatalf("MarshalWriteBinary(&buf, &testPrefixSet) failed: %v", err)
	}

	truncateModifyBuf := func(n int) func([]byte) []byte {
		return func(b []byte) []byte {
			if len(b) > n {
				return b[:n]
			}
			return b
		}
	}

	firstPrefixLenModifyBuf := func(bits byte) func([]byte) []byte {
		return func(b []byte) []byte {
			if len(b) >= 25 {
				b[24] = bits
			}
			return b
		}
	}

	expectErrUnexpectedEOF := func(t *testing.T, err error) {
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	}

	expectNonNilErr := func(t *testing.T, err error) {
		if err == nil {
			t.Errorf("err = nil, want non-nil error")
		}
	}

	for _, c := range [...]struct {
		name      string
		modifyBuf func([]byte) []byte
		checkErr  func(*testing.T, error)
	}{
		{
			name:      "MagicNumberTruncated",
			modifyBuf: truncateModifyBuf(4),
			checkErr:  expectErrUnexpectedEOF,
		},
		{
			name:      "IPv4CountTruncated",
			modifyBuf: truncateModifyBuf(12),
			checkErr:  expectErrUnexpectedEOF,
		},
		{
			name:      "IPv6CountTruncated",
			modifyBuf: truncateModifyBuf(20),
			checkErr:  expectErrUnexpectedEOF,
		},
		{
			name:      "AddressBytesTruncated",
			modifyBuf: truncateModifyBuf(buf.Len() - 1),
			checkErr:  expectErrUnexpectedEOF,
		},
		{
			name: "InvalidMagicNumber",
			modifyBuf: func(b []byte) []byte {
				if len(b) >= 8 {
					b[0] = 0x13
					b[1] = 0x37
					b[2] = 0x42
					b[3] = 0x69
					b[4] = 0xde
					b[5] = 0xad
					b[6] = 0xbe
					b[7] = 0xef
				}
				return b
			},
			checkErr: expectNonNilErr,
		},
		{
			name: "InvalidIPv4Count",
			modifyBuf: func(b []byte) []byte {
				if len(b) >= 16 {
					b[15]++
				}
				return b
			},
			checkErr: expectNonNilErr,
		},
		{
			name: "InvalidIPv6Count",
			modifyBuf: func(b []byte) []byte {
				if len(b) >= 24 {
					b[23]++
				}
				return b
			},
			checkErr: expectNonNilErr,
		},
		{
			name:      "InvalidPrefixLength/129",
			modifyBuf: firstPrefixLenModifyBuf(129),
			checkErr:  expectNonNilErr,
		},
		{
			name:      "InvalidPrefixLength/191",
			modifyBuf: firstPrefixLenModifyBuf(191),
			checkErr:  expectNonNilErr,
		},
		{
			name:      "InvalidPrefixLength/225",
			modifyBuf: firstPrefixLenModifyBuf(225),
			checkErr:  expectNonNilErr,
		},
		{
			name:      "InvalidPrefixLength/255",
			modifyBuf: firstPrefixLenModifyBuf(255),
			checkErr:  expectNonNilErr,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := slices.Clone(buf.Bytes())
			b = c.modifyBuf(b)
			var s bart.Lite
			err := prefixset.UnmarshalReadBinary(bytes.NewReader(b), &s)
			c.checkErr(t, err)
		})
	}
}

func TestConfigLoadPrefixSetError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken-prefixset.txt")
	if err := os.WriteFile(path, []byte("I'm not a prefix set!\n"), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", path, err)
	}

	cfg := prefixset.Config{
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

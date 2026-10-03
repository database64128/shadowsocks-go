package socks5_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
)

const (
	addrIP4Port    = 1080
	addrIP4In6Port = 1081
	addrIP6Port    = 1082
	addrDomainHost = "example.com"
	addrDomainPort = 443
)

var (
	addrIP4 = [socks5.IPv4AddrLen]byte{
		socks5.AtypIPv4,
		127, 0, 0, 1,
		byte(addrIP4Port >> 8), byte(addrIP4Port & 0xff),
	}
	addrIP4Addr     = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	addrIP4AddrPort = netip.AddrPortFrom(addrIP4Addr, addrIP4Port)
	addrIP4ConnAddr = conn.AddrFromIPPort(addrIP4AddrPort)

	addrIP4In6 = [socks5.IPv4AddrLen]byte{
		socks5.AtypIPv4,
		127, 0, 0, 1,
		byte(addrIP4In6Port >> 8), byte(addrIP4In6Port & 0xff),
	}
	addrIP4In6Addr     = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1})
	addrIP4In6AddrPort = netip.AddrPortFrom(addrIP4In6Addr, addrIP4In6Port)
	addrIP4In6ConnAddr = conn.AddrFromIPPort(addrIP4In6AddrPort)

	addrIP6 = [socks5.IPv6AddrLen]byte{
		socks5.AtypIPv6,
		0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e,
		byte(addrIP6Port >> 8), byte(addrIP6Port & 0xff),
	}
	addrIP6Addr     = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addrIP6AddrPort = netip.AddrPortFrom(addrIP6Addr, addrIP6Port)
	addrIP6ConnAddr = conn.AddrFromIPPort(addrIP6AddrPort)

	addrDomain = [1 + 1 + len(addrDomainHost) + 2]byte{
		socks5.AtypDomainName,
		byte(len(addrDomainHost)),
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		byte(addrDomainPort >> 8), byte(addrDomainPort & 0xff),
	}
	addrDomainConnAddr = conn.MustAddrFromDomainStringAndPort(addrDomainHost, addrDomainPort)

	addrDomainUpper = [1 + 1 + len(addrDomainHost) + 2]byte{
		socks5.AtypDomainName,
		byte(len(addrDomainHost)),
		'E', 'X', 'A', 'M', 'P', 'L', 'E', '.', 'C', 'O', 'M',
		byte(addrDomainPort >> 8), byte(addrDomainPort & 0xff),
	}
)

func mustPanic(t *testing.T, f func(), name string) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s did not panic", name)
}

var ipPortCases = [...]struct {
	name      string
	ipPort    netip.AddrPort
	wantBytes []byte
}{
	{
		name:      "Zero",
		ipPort:    netip.AddrPort{},
		wantBytes: socks5.IPv6UnspecifiedAddr[:],
	},
	{
		name:      "IPv4",
		ipPort:    addrIP4AddrPort,
		wantBytes: addrIP4[:],
	},
	{
		name:      "IPv4MappedIPv6",
		ipPort:    addrIP4In6AddrPort,
		wantBytes: addrIP4In6[:],
	},
	{
		name:      "IPv6",
		ipPort:    addrIP6AddrPort,
		wantBytes: addrIP6[:],
	},
}

func TestAppendAddrFromAddrPort(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			head := make([]byte, 32)
			rand.Read(head)
			buf := make([]byte, 0, 32+socks5.IPv6AddrLen)
			buf = append(buf, head...)

			full := socks5.AppendAddrFromAddrPort(buf, c.ipPort)
			if !bytes.Equal(full[:len(head)], head) {
				t.Errorf("AppendAddrFromAddrPort(buf, %q) modified buf[:%d]", c.ipPort, len(head))
			}
			if tail := full[len(head):]; !bytes.Equal(tail, c.wantBytes) {
				t.Errorf("AppendAddrFromAddrPort(buf, %q) appended %#v, want %#v", c.ipPort, slices.Clone(tail), c.wantBytes)
			}
		})
	}
}

func TestPutAddrFromAddrPort(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			full := make([]byte, 32)
			rand.Read(full)
			buf := make([]byte, 0, 32)
			buf = append(buf, full...)

			n := socks5.PutAddrFromAddrPort(buf, c.ipPort)
			if n != len(c.wantBytes) {
				t.Errorf("PutAddrFromAddrPort(buf, %q) = %d, want %d", c.ipPort, n, len(c.wantBytes))
			}
			if got := buf[:n]; !bytes.Equal(got, c.wantBytes) {
				t.Errorf("PutAddrFromAddrPort(buf, %q) stored %#v, want %#v", c.ipPort, slices.Clone(got), c.wantBytes)
			}
			if tail := buf[n:]; !bytes.Equal(tail, full[n:]) {
				t.Errorf("PutAddrFromAddrPort(buf, %q) modified buf[%d:]", c.ipPort, n)
			}
		})
	}
}

func TestPutAddrFromAddrPortPanic(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, len(c.wantBytes)-1, socks5.IPv6AddrLen)
			mustPanic(
				t,
				func() { socks5.PutAddrFromAddrPort(buf, c.ipPort) },
				fmt.Sprintf("PutAddrFromAddrPort(buf, %q)", c.ipPort),
			)
		})
	}
}

func TestLengthOfAddrFromAddrPort(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			if got := socks5.LengthOfAddrFromAddrPort(c.ipPort); got != len(c.wantBytes) {
				t.Errorf("LengthOfAddrFromAddrPort(%q) = %d, want %d", c.ipPort, got, len(c.wantBytes))
			}
		})
	}
}

func TestAppendAddrFromAddrPortAllocs(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 0, socks5.IPv6AddrLen)
			if n := testing.AllocsPerRun(10, func() {
				buf = socks5.AppendAddrFromAddrPort(buf[:0], c.ipPort)
			}); n > 0 {
				t.Errorf("AppendAddrFromAddrPort(buf, %q) allocs = %f, want 0", c.ipPort, n)
			}
		})
	}
}

func TestPutAddrFromAddrPortAllocs(t *testing.T) {
	for _, c := range ipPortCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, socks5.IPv6AddrLen)
			if n := testing.AllocsPerRun(10, func() {
				socks5.PutAddrFromAddrPort(buf, c.ipPort)
			}); n > 0 {
				t.Errorf("PutAddrFromAddrPort(buf, %q) allocs = %f, want 0", c.ipPort, n)
			}
		})
	}
}

func BenchmarkAppendAddrFromAddrPort(b *testing.B) {
	for _, c := range ipPortCases {
		b.Run(c.name, func(b *testing.B) {
			buf := make([]byte, 0, socks5.IPv6AddrLen)
			for b.Loop() {
				buf = socks5.AppendAddrFromAddrPort(buf[:0], c.ipPort)
			}
		})
	}
}

func BenchmarkPutAddrFromAddrPort(b *testing.B) {
	for _, c := range ipPortCases {
		b.Run(c.name, func(b *testing.B) {
			buf := make([]byte, socks5.IPv6AddrLen)
			for b.Loop() {
				socks5.PutAddrFromAddrPort(buf, c.ipPort)
			}
		})
	}
}

var connAddrCases = [...]struct {
	name      string
	addr      conn.Addr
	wantBytes []byte
}{
	{
		name:      "Zero",
		addr:      conn.Addr{},
		wantBytes: socks5.IPv4UnspecifiedAddr[:],
	},
	{
		name:      "IPv4",
		addr:      addrIP4ConnAddr,
		wantBytes: addrIP4[:],
	},
	{
		name:      "IPv4MappedIPv6",
		addr:      addrIP4In6ConnAddr,
		wantBytes: addrIP4In6[:],
	},
	{
		name:      "IPv6",
		addr:      addrIP6ConnAddr,
		wantBytes: addrIP6[:],
	},
	{
		name:      "Domain",
		addr:      addrDomainConnAddr,
		wantBytes: addrDomain[:],
	},
}

func TestAppendAddrFromConnAddr(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			head := make([]byte, 32)
			rand.Read(head)
			buf := make([]byte, 0, 32+socks5.MaxAddrLen)
			buf = append(buf, head...)

			full := socks5.AppendAddrFromConnAddr(buf, c.addr)
			if !bytes.Equal(full[:len(head)], head) {
				t.Errorf("AppendAddrFromConnAddr(buf, %q) modified buf[:%d]", c.addr, len(head))
			}
			if tail := full[len(head):]; !bytes.Equal(tail, c.wantBytes) {
				t.Errorf("AppendAddrFromConnAddr(buf, %q) appended %#v, want %#v", c.addr, slices.Clone(tail), c.wantBytes)
			}
		})
	}
}

func TestPutAddrFromConnAddr(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			full := make([]byte, 288)
			rand.Read(full)
			buf := make([]byte, 0, 288)
			buf = append(buf, full...)

			n := socks5.PutAddrFromConnAddr(buf, c.addr)
			if n != len(c.wantBytes) {
				t.Errorf("PutAddrFromConnAddr(buf, %q) = %d, want %d", c.addr, n, len(c.wantBytes))
			}
			if got := buf[:n]; !bytes.Equal(got, c.wantBytes) {
				t.Errorf("PutAddrFromConnAddr(buf, %q) stored %#v, want %#v", c.addr, slices.Clone(got), c.wantBytes)
			}
			if tail := buf[n:]; !bytes.Equal(tail, full[n:]) {
				t.Errorf("PutAddrFromConnAddr(buf, %q) modified buf[%d:]", c.addr, n)
			}
		})
	}
}

func TestPutAddrFromConnAddrPanic(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, len(c.wantBytes)-1, socks5.MaxAddrLen)
			mustPanic(
				t,
				func() { socks5.PutAddrFromConnAddr(buf, c.addr) },
				fmt.Sprintf("PutAddrFromConnAddr(buf, %q)", c.addr),
			)
		})
	}
}

func TestLengthOfAddrFromConnAddr(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			if got := socks5.LengthOfAddrFromConnAddr(c.addr); got != len(c.wantBytes) {
				t.Errorf("LengthOfAddrFromConnAddr(%q) = %d, want %d", c.addr, got, len(c.wantBytes))
			}
		})
	}
}

func TestAppendAddrFromConnAddrAllocs(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 0, socks5.MaxAddrLen)
			if n := testing.AllocsPerRun(10, func() {
				buf = socks5.AppendAddrFromConnAddr(buf[:0], c.addr)
			}); n > 0 {
				t.Errorf("AppendAddrFromConnAddr(buf, %q) allocs = %f, want 0", c.addr, n)
			}
		})
	}
}

func TestPutAddrFromConnAddrAllocs(t *testing.T) {
	for _, c := range connAddrCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, socks5.MaxAddrLen)
			if n := testing.AllocsPerRun(10, func() {
				socks5.PutAddrFromConnAddr(buf, c.addr)
			}); n > 0 {
				t.Errorf("PutAddrFromConnAddr(buf, %q) allocs = %f, want 0", c.addr, n)
			}
		})
	}
}

func BenchmarkAppendAddrFromConnAddr(b *testing.B) {
	for _, c := range connAddrCases {
		b.Run(c.name, func(b *testing.B) {
			buf := make([]byte, 0, socks5.MaxAddrLen)
			for b.Loop() {
				buf = socks5.AppendAddrFromConnAddr(buf[:0], c.addr)
			}
		})
	}
}

func BenchmarkPutAddrFromConnAddr(b *testing.B) {
	for _, c := range connAddrCases {
		b.Run(c.name, func(b *testing.B) {
			buf := make([]byte, socks5.MaxAddrLen)
			for b.Loop() {
				socks5.PutAddrFromConnAddr(buf, c.addr)
			}
		})
	}
}

var addrBytesCases = [...]struct {
	name       string
	data       []byte
	wantIPPort netip.AddrPort
	wantAddr   conn.Addr
}{
	{
		name:       "IPv4",
		data:       addrIP4[:],
		wantIPPort: addrIP4AddrPort,
		wantAddr:   addrIP4ConnAddr,
	},
	{
		name:       "IPv6",
		data:       addrIP6[:],
		wantIPPort: addrIP6AddrPort,
		wantAddr:   addrIP6ConnAddr,
	},
	{
		name:     "Domain",
		data:     addrDomain[:],
		wantAddr: addrDomainConnAddr,
	},
	{
		name:     "DomainUpper",
		data:     addrDomainUpper[:],
		wantAddr: addrDomainConnAddr,
	},
}

func TestAppendFromReader(t *testing.T) {
	for _, c := range addrBytesCases {
		t.Run(c.name, func(t *testing.T) {
			data := make([]byte, 0, socks5.MaxAddrLen+1)
			data = append(data, c.data...)
			r := bytes.NewReader(data)
			head := make([]byte, 32)
			rand.Read(head)
			buf := make([]byte, 0, 320)
			buf = append(buf, head...)

			full, err := socks5.AppendAddrFromReader(buf, r)
			if err != nil {
				t.Fatalf("AppendFromReader() failed: %v", err)
			}
			if !bytes.Equal(full[:len(head)], head) {
				t.Errorf("AppendFromReader() modified buf[:%d]", len(head))
			}
			if tail := full[len(head):]; !bytes.Equal(tail, c.data) {
				t.Errorf("AppendFromReader() = %#v, want %#v", tail, c.data)
			}
			if n := len(data) - r.Len(); n != len(c.data) {
				t.Errorf("AppendFromReader() read %d bytes, want %d", n, len(c.data))
			}
		})
	}
}

func TestConnAddrFromReader(t *testing.T) {
	for _, c := range addrBytesCases {
		t.Run(c.name, func(t *testing.T) {
			data := make([]byte, 0, socks5.MaxAddrLen+1)
			data = append(data, c.data...)
			r := bytes.NewReader(data)
			buf := make([]byte, 0, socks5.MaxAddrLen)

			addr, err := socks5.ConnAddrFromReader(r, buf)
			if err != nil {
				t.Fatalf("ConnAddrFromReader() failed: %v", err)
			}
			if addr != c.wantAddr {
				t.Errorf("ConnAddrFromReader() = %q, want %q", addr, c.wantAddr)
			}
			if n := len(data) - r.Len(); n != len(c.data) {
				t.Errorf("ConnAddrFromReader() read %d bytes, want %d", n, len(c.data))
			}
		})
	}
}

func TestAddrPortFromBytes(t *testing.T) {
	for _, c := range addrBytesCases {
		if !c.wantIPPort.IsValid() {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 32)
			rand.Read(buf)
			copy(buf, c.data)
			full := make([]byte, 0, 32)
			full = append(full, buf...)

			ipPort, n, err := socks5.AddrPortFromBytes(buf)
			if err != nil {
				t.Fatalf("AddrPortFromBytes() failed: %v", err)
			}
			if n != len(c.data) {
				t.Errorf("AddrPortFromBytes() consumed %d bytes, want %d", n, len(c.data))
			}
			if ipPort != c.wantIPPort {
				t.Errorf("AddrPortFromBytes() = %q, want %q", ipPort, c.wantIPPort)
			}
			if !bytes.Equal(buf, full) {
				t.Error("AddrPortFromBytes() modified input buffer")
			}
		})
	}
}

func TestConnAddrFromBytes(t *testing.T) {
	for _, c := range addrBytesCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 288)
			n := copy(buf, c.data)
			rand.Read(buf[n:])
			full := make([]byte, 0, 288)
			full = append(full, buf...)

			addr, n, err := socks5.ConnAddrFromBytes(buf)
			if err != nil {
				t.Fatalf("ConnAddrFromBytes() failed: %v", err)
			}
			if n != len(c.data) {
				t.Errorf("ConnAddrFromBytes() consumed %d bytes, want %d", n, len(c.data))
			}
			if addr != c.wantAddr {
				t.Errorf("ConnAddrFromBytes() = %q, want %q", addr, c.wantAddr)
			}
			if !bytes.Equal(buf[n:], full[n:]) {
				t.Errorf("ConnAddrFromBytes() modified buf[%d:]", n)
			}
		})
	}
}

func TestDomainCacheConnAddrFromBytes(t *testing.T) {
	var dc socks5.DomainCache
	for _, c := range addrBytesCases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 288)
			n := copy(buf, c.data)
			rand.Read(buf[n:])
			full := make([]byte, 0, 288)
			full = append(full, buf...)

			addr, n, err := dc.ConnAddrFromBytes(buf)
			if err != nil {
				t.Fatalf("dc.ConnAddrFromBytes() failed: %v", err)
			}
			if n != len(c.data) {
				t.Errorf("dc.ConnAddrFromBytes() consumed %d bytes, want %d", n, len(c.data))
			}
			if addr != c.wantAddr {
				t.Errorf("dc.ConnAddrFromBytes() = %q, want %q", addr, c.wantAddr)
			}
			if !bytes.Equal(buf[n:], full[n:]) {
				t.Errorf("dc.ConnAddrFromBytes() modified buf[%d:]", n)
			}
		})
	}
}

func BenchmarkAppendFromReader(b *testing.B) {
	for _, c := range addrBytesCases {
		b.Run(c.name, func(b *testing.B) {
			var r bytes.Reader
			buf := make([]byte, 0, socks5.MaxAddrLen)
			for b.Loop() {
				r.Reset(c.data)
				buf, _ = socks5.AppendAddrFromReader(buf[:0], &r)
			}
		})
	}
}

func BenchmarkConnAddrFromReader(b *testing.B) {
	for _, c := range addrBytesCases {
		b.Run(c.name, func(b *testing.B) {
			var r bytes.Reader
			buf := make([]byte, 0, socks5.MaxAddrLen)
			for b.Loop() {
				r.Reset(c.data)
				_, _ = socks5.ConnAddrFromReader(&r, buf)
			}
		})
	}
}

func BenchmarkAddrPortFromBytes(b *testing.B) {
	for _, c := range addrBytesCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_, _, _ = socks5.AddrPortFromBytes(c.data)
			}
		})
	}
}

func BenchmarkConnAddrFromBytes(b *testing.B) {
	for _, c := range addrBytesCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_, _, _ = socks5.ConnAddrFromBytes(c.data)
			}
		})
	}
}

func BenchmarkDomainCacheConnAddrFromBytes(b *testing.B) {
	var dc socks5.DomainCache
	for _, c := range addrBytesCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_, _, _ = dc.ConnAddrFromBytes(c.data)
			}
		})
	}
}

var addrBytesErrorCases = [...]struct {
	name          string
	data          []byte
	checkReadErr  func(*testing.T, error)
	checkBytesErr func(*testing.T, error)
	isBadDomain   bool
}{
	{
		name:          "Empty",
		data:          nil,
		checkReadErr:  expectErrUnexpectedEOF,
		checkBytesErr: expectNotEnoughBytesError(0, 0),
	},
	{
		name:          "IPv4Truncated",
		data:          addrIP4[:len(addrIP4)-1],
		checkReadErr:  expectErrUnexpectedEOF,
		checkBytesErr: expectNotEnoughBytesError(uint16(len(addrIP4)-1), socks5.AtypIPv4),
	},
	{
		name:          "IPv6Truncated",
		data:          addrIP6[:len(addrIP6)-1],
		checkReadErr:  expectErrUnexpectedEOF,
		checkBytesErr: expectNotEnoughBytesError(uint16(len(addrIP6)-1), socks5.AtypIPv6),
	},
	{
		name:          "DomainTruncated",
		data:          addrDomain[:len(addrDomain)-1],
		checkReadErr:  expectErrUnexpectedEOF,
		checkBytesErr: expectNotEnoughBytesError(uint16(len(addrDomain)-1), socks5.AtypDomainName),
	},
	{
		name:          "InvalidATYP",
		data:          []byte{2, 0, 0, 0, 0, 0, 0},
		checkReadErr:  expectInvalidATYPError(2),
		checkBytesErr: expectInvalidATYPError(2),
	},
	{
		name:          "ZeroLengthDomain",
		data:          []byte{socks5.AtypDomainName, 0, 0, 0},
		checkReadErr:  expectNonNilError,
		checkBytesErr: expectNonNilError,
		isBadDomain:   true,
	},
}

func expectNonNilError(t *testing.T, err error) {
	if err == nil {
		t.Error("err = nil, want non-nil error")
	}
}

func expectErrUnexpectedEOF(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func expectInvalidATYPError(wantATYP byte) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		e, ok := errors.AsType[socks5.InvalidATYPError](err)
		if !ok {
			t.Errorf("error = %v, want %T", err, e)
			return
		}
		if atyp := byte(e); atyp != wantATYP {
			t.Errorf("error ATYP = %#x, want %#x", atyp, wantATYP)
		}
	}
}

func expectNotEnoughBytesError(wantLen uint16, wantATYP byte) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		e, ok := errors.AsType[socks5.NotEnoughBytesError](err)
		if !ok {
			t.Errorf("error = %v, want %T", err, e)
			return
		}
		if e.Len != wantLen {
			t.Errorf("e.Len = %d, want %d", e.Len, wantLen)
		}
		if e.ATYP != wantATYP {
			t.Errorf("e.ATYP = %#x, want %#x", e.ATYP, wantATYP)
		}
	}
}

func TestAppendAddrFromReaderError(t *testing.T) {
	for _, c := range addrBytesErrorCases {
		if c.isBadDomain {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewReader(c.data)
			buf := make([]byte, 0, socks5.MaxAddrLen)
			buf, err := socks5.AppendAddrFromReader(buf, r)
			c.checkReadErr(t, err)
		})
	}
}

func TestConnAddrFromReaderError(t *testing.T) {
	for _, c := range addrBytesErrorCases {
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewReader(c.data)
			buf := make([]byte, 0, socks5.MaxAddrLen)
			addr, err := socks5.ConnAddrFromReader(r, buf)
			c.checkReadErr(t, err)
			if addr.IsValid() {
				t.Errorf("addr = %q, want zero value", addr)
			}
		})
	}
}

func TestConnAddrFromBytesError(t *testing.T) {
	for _, c := range addrBytesErrorCases {
		t.Run(c.name, func(t *testing.T) {
			addr, n, err := socks5.ConnAddrFromBytes(c.data)
			c.checkBytesErr(t, err)
			if n > len(c.data) {
				t.Errorf("n = %d, want <= %d", n, len(c.data))
			}
			if addr.IsValid() {
				t.Errorf("addr = %q, want zero value", addr)
			}
		})
	}
}

func TestDomainCacheConnAddrFromBytesError(t *testing.T) {
	var dc socks5.DomainCache
	for _, c := range addrBytesErrorCases {
		t.Run(c.name, func(t *testing.T) {
			addr, n, err := dc.ConnAddrFromBytes(c.data)
			c.checkBytesErr(t, err)
			if n > len(c.data) {
				t.Errorf("n = %d, want <= %d", n, len(c.data))
			}
			if addr.IsValid() {
				t.Errorf("addr = %q, want zero value", addr)
			}
		})
	}
}

func TestAddrPortFromBytesError(t *testing.T) {
	for _, c := range [...]struct {
		name     string
		data     []byte
		checkErr func(*testing.T, error)
	}{
		{
			name:     "Empty",
			data:     nil,
			checkErr: expectNotEnoughBytesError(0, 0),
		},
		{
			name:     "IPv4Truncated",
			data:     addrIP4[:len(addrIP4)-1],
			checkErr: expectNotEnoughBytesError(uint16(len(addrIP4)-1), 0),
		},
		{
			name:     "IPv6Truncated",
			data:     addrIP6[:len(addrIP6)-1],
			checkErr: expectNotEnoughBytesError(uint16(len(addrIP6)-1), socks5.AtypIPv6),
		},
		{
			name: "Domain",
			data: addrDomain[:],
			checkErr: func(t *testing.T, err error) {
				if !errors.Is(err, socks5.ErrAddrDomain) {
					t.Errorf("err = %v, want socks5.ErrAddrDomain", err)
				}
			},
		},
		{
			name:     "InvalidATYP",
			data:     []byte{2, 0, 0, 0, 0, 0, 0},
			checkErr: expectInvalidATYPError(2),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, n, err := socks5.AddrPortFromBytes(c.data)
			c.checkErr(t, err)
			if n > len(c.data) {
				t.Errorf("n = %d, want <= %d", n, len(c.data))
			}
			if addr.IsValid() {
				t.Errorf("addr = %q, want zero value", addr)
			}
		})
	}
}

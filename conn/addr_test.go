package conn

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
)

const (
	addrZeroPort     = 0
	addrZeroString   = ""
	addrIPHost       = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addrIPPort       = 1080
	addrIPString     = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
	addrDomainHost   = "example.com"
	addrDomainPort   = 443
	addrDomainString = "example.com:443"

	maxTestAddrTextLen = max(len(addrZeroString), len(addrIPString), len(addrDomainString))
)

var (
	addrZero       Addr
	addrIP         = AddrFromIPPort(addrIPAddrPort)
	addrIPAddr     = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addrIPAddrPort = netip.AddrPortFrom(addrIPAddr, addrIPPort)
	addrDomain     = MustAddrFromDomainPort(addrDomainHost, addrDomainPort)
)

func TestAddrEquals(t *testing.T) {
	addrIP443 := AddrFromIPAndPort(addrIPAddr, 443)
	addrDomain80 := MustAddrFromDomainPort(addrDomainHost, 80)

	for _, c := range []struct {
		a, b Addr
		eq   bool
	}{
		{addrZero, addrZero, true},
		{addrZero, addrIP, false},
		{addrZero, addrDomain, false},
		{addrZero, addrIP443, false},
		{addrZero, addrDomain80, false},
		{addrIP, addrZero, false},
		{addrIP, addrIP, true},
		{addrIP, addrDomain, false},
		{addrIP, addrIP443, false},
		{addrIP, addrDomain80, false},
		{addrDomain, addrZero, false},
		{addrDomain, addrIP, false},
		{addrDomain, addrDomain, true},
		{addrDomain, addrIP443, false},
		{addrDomain, addrDomain80, false},
		{addrIP443, addrZero, false},
		{addrIP443, addrIP, false},
		{addrIP443, addrDomain, false},
		{addrIP443, addrIP443, true},
		{addrIP443, addrDomain80, false},
		{addrDomain80, addrZero, false},
		{addrDomain80, addrIP, false},
		{addrDomain80, addrDomain, false},
		{addrDomain80, addrIP443, false},
		{addrDomain80, addrDomain80, true},
	} {
		if eq := c.a.Equals(c.b); eq != c.eq {
			t.Errorf("%q.Equals(%q) = %t, want %t", c.a, c.b, eq, c.eq)
		}
	}
}

func TestAddrIsValid(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, true},
		{addrDomain, true},
	} {
		if v := c.a.IsValid(); v != c.v {
			t.Errorf("%q.IsValid() = %t, want %t", c.a, v, c.v)
		}
	}
}

func TestAddrIsIP(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, true},
		{addrDomain, false},
	} {
		if v := c.a.IsIP(); v != c.v {
			t.Errorf("%q.IsIP() = %t, want %t", c.a, v, c.v)
		}
	}
}

func TestAddrIsDomain(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, false},
		{addrDomain, true},
	} {
		if v := c.a.IsDomain(); v != c.v {
			t.Errorf("%q.IsDomain() = %t, want %t", c.a, v, c.v)
		}
	}
}

func mustPanic(t *testing.T, f func(), name string) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s did not panic", name)
}

func TestAddrIP(t *testing.T) {
	if ip := addrIP.IP(); ip != addrIPAddr {
		t.Errorf("%q.IP() = %q, want %q", addrIP, ip, addrIPAddr)
	}

	mustPanic(t, func() { _ = addrZero.IP() }, "addrZero.IP()")
	mustPanic(t, func() { _ = addrDomain.IP() }, "addrDomain.IP()")
}

func TestAddrDomain(t *testing.T) {
	if domain := addrDomain.Domain(); domain != addrDomainHost {
		t.Errorf("%q.Domain() = %q, want %q", addrDomain, domain, addrDomainHost)
	}

	mustPanic(t, func() { _ = addrZero.Domain() }, "addrZero.Domain()")
	mustPanic(t, func() { _ = addrIP.Domain() }, "addrIP.Domain()")
}

func TestAddrPort(t *testing.T) {
	for _, c := range []struct {
		a Addr
		p uint16
	}{
		{addrZero, addrZeroPort},
		{addrIP, addrIPPort},
		{addrDomain, addrDomainPort},
	} {
		if p := c.a.Port(); p != c.p {
			t.Errorf("%q.Port() = %d, want %d", c.a, p, c.p)
		}
	}
}

func TestAddrIPPort(t *testing.T) {
	if ap := addrIP.IPPort(); ap != addrIPAddrPort {
		t.Errorf("%q.IPPort() = %q, want %q", addrIP, ap, addrIPAddrPort)
	}

	mustPanic(t, func() { _ = addrZero.IPPort() }, "addrZero.IPPort()")
	mustPanic(t, func() { _ = addrDomain.IPPort() }, "addrDomain.IPPort()")
}

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil, net.UnknownNetworkError(network)
	}

	ips, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return ips, nil
}

var addrFakeResolver = fakeResolver{
	"example.com": {
		addrIPAddr,
		netip.AddrFrom4([4]byte{127, 0, 0, 1}),
	},
}

func TestAddrResolveIP(t *testing.T) {
	ctx := t.Context()

	for _, c := range [...]struct {
		name       string
		addr       Addr
		expectedIP netip.Addr
	}{
		{"IP", addrIP, addrIPAddr},
		{"Domain", addrDomain, addrIPAddr},
	} {
		t.Run(c.name, func(t *testing.T) {
			ip, err := c.addr.ResolveIP(ctx, "ip", addrFakeResolver)
			if err != nil {
				t.Fatal(err)
			}
			if ip != c.expectedIP {
				t.Errorf("%q.ResolveIP() = %q, want %q", c.addr, ip, c.expectedIP)
			}
		})
	}

	mustPanic(t, func() { _, _ = addrZero.ResolveIP(ctx, "ip", addrFakeResolver) }, "addrZero.ResolveIP()")
}

func TestAddrResolveIPPort(t *testing.T) {
	ctx := t.Context()

	for _, c := range [...]struct {
		name           string
		addr           Addr
		expectedIPPort netip.AddrPort
	}{
		{"IP", addrIP, addrIPAddrPort},
		{"Domain", addrDomain, netip.AddrPortFrom(addrIPAddr, addrDomainPort)},
	} {
		t.Run(c.name, func(t *testing.T) {
			ipPort, err := c.addr.ResolveIPPort(ctx, "ip", addrFakeResolver)
			if err != nil {
				t.Fatal(err)
			}
			if ipPort != c.expectedIPPort {
				t.Errorf("%q.ResolveIPPort() = %q, want %q", c.addr, ipPort, c.expectedIPPort)
			}
		})
	}

	mustPanic(t, func() { _, _ = addrZero.ResolveIPPort(ctx, "ip", addrFakeResolver) }, "addrZero.ResolveIPPort()")
}

func TestAddrHost(t *testing.T) {
	if host := addrIP.Host(); host != addrIPHost {
		t.Errorf("%q.Host() = %q, want %q", addrIP, host, addrIPHost)
	}

	if host := addrDomain.Host(); host != addrDomainHost {
		t.Errorf("%q.Host() = %q, want %q", addrDomain, host, addrDomainHost)
	}

	mustPanic(t, func() { _ = addrZero.Host() }, "addrZero.Host()")
}

var addrTextCases = [...]struct {
	name string
	addr Addr
	text string
}{
	{"Zero", addrZero, addrZeroString},
	{"IP", addrIP, addrIPString},
	{"Domain", addrDomain, addrDomainString},
}

func TestAddrString(t *testing.T) {
	for _, c := range addrTextCases {
		if s := c.addr.String(); s != c.text {
			t.Errorf("%q.String() = %q, want %q", c.addr, s, c.text)
		}
	}
}

func TestAddrAppendTo(t *testing.T) {
	head := make([]byte, 64)
	rand.Read(head)

	b := make([]byte, 64, 128)
	_ = copy(b, head)

	for _, c := range addrTextCases {
		full := c.addr.AppendTo(b)
		if !bytes.Equal(full[:len(b)], head) {
			t.Errorf("%q.AppendTo() modified b[:len(b)]", c.addr)
		}
		if tail := full[len(b):]; string(tail) != c.text {
			t.Errorf("%q.AppendTo() = %q, want %q", c.addr, tail, c.text)
		}
	}
}

func TestAddrAppendText(t *testing.T) {
	head := make([]byte, 64)
	rand.Read(head)

	b := make([]byte, 64, 128)
	_ = copy(b, head)

	for _, c := range addrTextCases {
		full, err := c.addr.AppendText(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(full[:len(b)], head) {
			t.Errorf("%q.AppendText() modified b[:len(b)]", c.addr)
		}
		if tail := full[len(b):]; string(tail) != c.text {
			t.Errorf("%q.AppendText() = %q, want %q", c.addr, tail, c.text)
		}
	}
}

func TestAddrStringAllocs(t *testing.T) {
	for _, c := range [...]struct {
		name   string
		addr   Addr
		allocs int
	}{
		{"Zero", addrZero, 0},
		{"IP", addrIP, 1},
		{"Domain", addrDomain, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := testing.AllocsPerRun(10, func() {
				_ = c.addr.String()
			})
			if n != float64(c.allocs) {
				t.Errorf("%q.String() allocs = %f, want %d", c.addr, n, c.allocs)
			}
		})
	}
}

func TestAddrAppendToAllocs(t *testing.T) {
	b := make([]byte, 0, maxTestAddrTextLen)
	for _, c := range addrTextCases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "Domain" {
				t.Skip("TODO optimization")
			}
			if n := testing.AllocsPerRun(10, func() {
				b = c.addr.AppendTo(b[:0])
			}); n > 0 {
				t.Errorf("%q.AppendTo() allocs = %f, want 0", c.addr, n)
			}
		})
	}
}

func TestAddrAppendTextAllocs(t *testing.T) {
	b := make([]byte, 0, maxTestAddrTextLen)
	for _, c := range addrTextCases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "Domain" {
				t.Skip("TODO optimization")
			}
			if n := testing.AllocsPerRun(10, func() {
				b, _ = c.addr.AppendText(b[:0])
			}); n > 0 {
				t.Errorf("%q.AppendText() allocs = %f, want 0", c.addr, n)
			}
		})
	}
}

func BenchmarkAddrString(b *testing.B) {
	for _, c := range addrTextCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_ = c.addr.String()
			}
		})
	}
}

func BenchmarkAddrAppendTo(b *testing.B) {
	buf := make([]byte, 0, maxTestAddrTextLen)
	for _, c := range addrTextCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				buf = c.addr.AppendTo(buf[:0])
			}
		})
	}
}

func BenchmarkAddrAppendText(b *testing.B) {
	buf := make([]byte, 0, maxTestAddrTextLen)
	for _, c := range addrTextCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				buf, _ = c.addr.AppendText(buf[:0])
			}
		})
	}
}

func TestAddrMarshalAndUnmarshalText(t *testing.T) {
	for _, c := range addrTextCases {
		text, err := c.addr.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if string(text) != c.text {
			t.Errorf("%q.MarshalText() = %q, want %q", c.addr, text, c.text)
		}

		var addr Addr
		if err = addr.UnmarshalText(text); err != nil {
			t.Fatal(err)
		}
		if !addr.Equals(c.addr) {
			t.Errorf("addr.UnmarshalText(%q) = %q, want %q", text, addr, c.addr)
		}
	}
}

func TestAddrMarshalTextAllocs(t *testing.T) {
	for _, c := range addrTextCases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "Domain" {
				t.Skip("TODO optimization")
			}
			if n := testing.AllocsPerRun(10, func() {
				_, _ = c.addr.MarshalText()
			}); n > 1 {
				t.Errorf("%q.MarshalText() allocs = %f, want <= 1", c.addr, n)
			}
		})
	}
}

func BenchmarkAddrUnmarshalText(b *testing.B) {
	for _, c := range addrTextCases {
		b.Run(c.name, func(b *testing.B) {
			var addr Addr
			text := []byte(c.text)
			for b.Loop() {
				if err := addr.UnmarshalText(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestAddrFromDomainPort(t *testing.T) {
	for _, c := range []struct {
		name   string
		domain string
		port   uint16
	}{
		{"EmptyDomain", "", 443},
		{"LongDomain", strings.Repeat(" ", 256), 443},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AddrFromDomainPort(c.domain, c.port); err == nil {
				t.Errorf("AddrFromDomainPort(%q, %d) did not return error.", c.domain, c.port)
			}
		})
	}
}

func TestAddrFromDomainPortAllocs(t *testing.T) {
	if n := testing.AllocsPerRun(10, func() {
		_, _ = AddrFromDomainPort(addrDomainHost, addrDomainPort)
	}); n > 0 {
		t.Errorf("AddrFromDomainPort(%q, %d) allocs = %f, want 0", addrDomainHost, addrDomainPort, n)
	}
}

func TestAddrFromHostPort(t *testing.T) {
	t.Run("EmptyHost", func(t *testing.T) {
		if _, err := AddrFromHostPort("", addrZeroPort); err == nil {
			t.Error("AddrFromHostPort(\"\", addrZeroPort) did not return an error")
		}
	})

	for _, c := range []struct {
		name         string
		host         string
		port         uint16
		expectedAddr Addr
	}{
		{"IP", addrIPHost, addrIPPort, addrIP},
		{"Domain", addrDomainHost, addrDomainPort, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := AddrFromHostPort(c.host, c.port)
			if err != nil {
				t.Fatal(err)
			}
			if !addr.Equals(c.expectedAddr) {
				t.Errorf("AddrFromHostPort(%q, %d) = %q, want %q", c.host, c.port, addr, c.expectedAddr)
			}
		})
	}
}

func TestAddrFromHostPortAllocs(t *testing.T) {
	// Currently we can only guarantee zero allocations for IP hosts.
	// For domain hosts, [netip.ParseAddr] allocates an error.
	// See https://github.com/golang/go/issues/76766.
	if n := testing.AllocsPerRun(10, func() {
		_, _ = AddrFromHostPort(addrIPHost, addrIPPort)
	}); n > 0 {
		t.Errorf("AddrFromHostPort(%q, %d) allocs = %f, want 0", addrIPHost, addrIPPort, n)
	}
}

func TestAddrParsing(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		if _, err := ParseAddr(""); err == nil {
			t.Error("ParseAddr(\"\") did not return error.")
		}
	})

	for _, c := range []struct {
		name         string
		text         string
		expectedAddr Addr
	}{
		{"IP", addrIPString, addrIP},
		{"Domain", addrDomainString, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := ParseAddr(c.text)
			if err != nil {
				t.Fatal(err)
			}
			if !addr.Equals(c.expectedAddr) {
				t.Errorf("ParseAddr(%q) = %q, want %q", c.text, addr, c.expectedAddr)
			}
		})
	}
}

func TestAddrParsingAllocs(t *testing.T) {
	if n := testing.AllocsPerRun(10, func() {
		_, _ = ParseAddr(addrIPString)
	}); n > 0 {
		t.Errorf("ParseAddr(%q) allocs = %f, want 0", addrIPString, n)
	}
}

var (
	addrPort4    = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1080)
	addrPort4in6 = netip.AddrPortFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), 1080)
)

func TestAddrPortMappedEqual(t *testing.T) {
	for _, c := range []struct {
		a, b netip.AddrPort
		eq   bool
	}{
		{addrPort4, addrPort4, true},
		{addrPort4, addrPort4in6, true},
		{addrPort4in6, addrPort4in6, true},
		{addrPort4, addrIPAddrPort, false},
		{addrPort4in6, addrIPAddrPort, false},
	} {
		if eq := AddrPortMappedEqual(c.a, c.b); eq != c.eq {
			t.Errorf("AddrPortMappedEqual(%q, %q) = %t, want %t", c.a, c.b, eq, c.eq)
		}
	}
}

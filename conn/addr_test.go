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
	addrZeroPort   = 0
	addrZeroString = ""

	addrIP4Host   = "192.0.2.1"
	addrIP4Port   = 80
	addrIP4String = "192.0.2.1:80"

	addrIP4In6Host   = "::ffff:192.0.2.2"
	addrIP4In6Port   = 8080
	addrIP4In6String = "[::ffff:192.0.2.2]:8080"

	addrIP4In6ZoneHost   = "::ffff:192.0.2.3%lo"
	addrIP4In6ZonePort   = 10080
	addrIP4In6ZoneString = "[::ffff:192.0.2.3%lo]:10080"

	addrIP6Host   = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addrIP6Port   = 1080
	addrIP6String = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"

	addrDomainHost   = "example.com"
	addrDomainPort   = 443
	addrDomainString = "example.com:443"

	maxTestAddrTextLen = max(len(addrZeroString), len(addrIP6String), len(addrDomainString))
)

var (
	addrZero Addr

	addrIP4         = AddrFromIPPort(addrIP4AddrPort)
	addrIP4Addr     = netip.AddrFrom4([4]byte{192, 0, 2, 1})
	addrIP4AddrPort = netip.AddrPortFrom(addrIP4Addr, addrIP4Port)

	addrIP4In6         = AddrFromIPPort(addrIP4In6AddrPort)
	addrIP4In6Addr     = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 192, 0, 2, 2})
	addrIP4In6AddrPort = netip.AddrPortFrom(addrIP4In6Addr, addrIP4In6Port)

	addrIP4In6Zone         = AddrFromIPPort(addrIP4In6ZoneAddrPort)
	addrIP4In6ZoneAddr     = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 192, 0, 2, 3}).WithZone("lo")
	addrIP4In6ZoneAddrPort = netip.AddrPortFrom(addrIP4In6ZoneAddr, addrIP4In6ZonePort)

	addrIP6         = AddrFromIPPort(addrIP6AddrPort)
	addrIP6Addr     = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addrIP6AddrPort = netip.AddrPortFrom(addrIP6Addr, addrIP6Port)

	addrDomain      = AddrFromDomainPort(addrTypedDomain, addrDomainPort)
	addrTypedDomain = MustDomainFromString(addrDomainHost)
)

func TestAddrIsValid(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP4, true},
		{addrIP4In6, true},
		{addrIP4In6Zone, true},
		{addrIP6, true},
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
		{addrIP4, true},
		{addrIP4In6, true},
		{addrIP4In6Zone, true},
		{addrIP6, true},
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
		{addrIP4, false},
		{addrIP4In6, false},
		{addrIP4In6Zone, false},
		{addrIP6, false},
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
	for _, c := range [...]struct {
		addr Addr
		want netip.Addr
	}{
		{addrIP4, addrIP4Addr},
		{addrIP4In6, addrIP4In6Addr},
		{addrIP4In6Zone, addrIP4In6ZoneAddr},
		{addrIP6, addrIP6Addr},
	} {
		if ip := c.addr.IP(); ip != c.want {
			t.Errorf("%q.IP() = %q, want %q", c.addr, ip, c.want)
		}
	}
}

func TestAddrIPPanic(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
	}{
		{
			name: "addrZero.IP()",
			addr: addrZero,
		},
		{
			name: "addrDomain.IP()",
			addr: addrDomain,
		},
	} {
		mustPanic(t, func() { _ = c.addr.IP() }, c.name)
	}
}

func TestAddrDomain(t *testing.T) {
	if domain := addrDomain.Domain(); domain != addrTypedDomain {
		t.Errorf("%q.Domain() = %q, want %q", addrDomain, domain, addrTypedDomain)
	}
}

func TestAddrDomainPanic(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
	}{
		{
			name: "addrZero.Domain()",
			addr: addrZero,
		},
		{
			name: "addrIP4.Domain()",
			addr: addrIP4,
		},
		{
			name: "addrIP4In6.Domain()",
			addr: addrIP4In6,
		},
		{
			name: "addrIP4In6Zone.Domain()",
			addr: addrIP4In6Zone,
		},
		{
			name: "addrIP6.Domain()",
			addr: addrIP6,
		},
	} {
		mustPanic(t, func() { _ = c.addr.Domain() }, c.name)
	}
}

func TestAddrDomainLen(t *testing.T) {
	for _, c := range [...]struct {
		addr Addr
		want int
	}{
		{
			addr: MustAddrFromDomainStringAndPort("example.com", 80),
			want: len("example.com"),
		},
		{
			addr: MustAddrFromDomainStringAndPort("example.com.", 80),
			want: len("example.com."),
		},
	} {
		if got := c.addr.DomainLen(); got != c.want {
			t.Errorf("%q.DomainLen() = %d, want %d", c.addr, got, c.want)
		}
	}
}

func TestAddrDomainLenPanic(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
	}{
		{
			name: "addrZero.DomainLen()",
			addr: addrZero,
		},
		{
			name: "addrIP4.DomainLen()",
			addr: addrIP4,
		},
		{
			name: "addrIP4In6.DomainLen()",
			addr: addrIP4In6,
		},
		{
			name: "addrIP4In6Zone.DomainLen()",
			addr: addrIP4In6Zone,
		},
		{
			name: "addrIP6.DomainLen()",
			addr: addrIP6,
		},
	} {
		mustPanic(t, func() { _ = c.addr.DomainLen() }, c.name)
	}
}

func TestAddrPort(t *testing.T) {
	for _, c := range []struct {
		a Addr
		p uint16
	}{
		{addrZero, addrZeroPort},
		{addrIP4, addrIP4Port},
		{addrIP4In6, addrIP4In6Port},
		{addrIP4In6Zone, addrIP4In6ZonePort},
		{addrIP6, addrIP6Port},
		{addrDomain, addrDomainPort},
	} {
		if p := c.a.Port(); p != c.p {
			t.Errorf("%q.Port() = %d, want %d", c.a, p, c.p)
		}
	}
}

func TestAddrIPPort(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
		want netip.AddrPort
	}{
		{"addrIP4", addrIP4, addrIP4AddrPort},
		{"addrIP4In6", addrIP4In6, addrIP4In6AddrPort},
		{"addrIP4In6Zone", addrIP4In6Zone, addrIP4In6ZoneAddrPort},
		{"addrIP6", addrIP6, addrIP6AddrPort},
	} {
		if ap := c.addr.IPPort(); ap != c.want {
			t.Errorf("%q.IPPort() = %q, want %q", c.addr, ap, c.want)
		}
	}
}

func TestAddrIPPortPanic(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
	}{
		{"addrZero.IPPort()", addrZero},
		{"addrDomain.IPPort()", addrDomain},
	} {
		mustPanic(t, func() { _ = c.addr.IPPort() }, c.name)
	}
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
		addrIP6Addr,
		addrIP4Addr,
	},
}

func TestAddrResolveIP(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
		want netip.Addr
	}{
		{"IP4", addrIP4, addrIP4Addr},
		{"IP4In6", addrIP4In6, addrIP4In6Addr},
		{"IP4In6Zone", addrIP4In6Zone, addrIP4In6ZoneAddr},
		{"IP6", addrIP6, addrIP6Addr},
		{"Domain", addrDomain, addrIP6Addr},
	} {
		t.Run(c.name, func(t *testing.T) {
			ip, err := c.addr.ResolveIP(t.Context(), "ip", addrFakeResolver)
			if err != nil {
				t.Fatal(err)
			}
			if ip != c.want {
				t.Errorf("%q.ResolveIP() = %q, want %q", c.addr, ip, c.want)
			}
		})
	}
}

func TestAddrResolveIPPanic(t *testing.T) {
	mustPanic(t, func() { _, _ = addrZero.ResolveIP(t.Context(), "ip", addrFakeResolver) }, "addrZero.ResolveIP()")
}

func TestAddrResolveIPPort(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
		want netip.AddrPort
	}{
		{"IP4", addrIP4, netip.AddrPortFrom(addrIP4Addr, addrIP4Port)},
		{"IP4In6", addrIP4In6, netip.AddrPortFrom(addrIP4In6Addr, addrIP4In6Port)},
		{"IP4In6Zone", addrIP4In6Zone, netip.AddrPortFrom(addrIP4In6ZoneAddr, addrIP4In6ZonePort)},
		{"IP6", addrIP6, addrIP6AddrPort},
		{"Domain", addrDomain, netip.AddrPortFrom(addrIP6Addr, addrDomainPort)},
	} {
		t.Run(c.name, func(t *testing.T) {
			ipPort, err := c.addr.ResolveIPPort(t.Context(), "ip", addrFakeResolver)
			if err != nil {
				t.Fatal(err)
			}
			if ipPort != c.want {
				t.Errorf("%q.ResolveIPPort() = %q, want %q", c.addr, ipPort, c.want)
			}
		})
	}
}

func TestAddrResolveIPPortPanic(t *testing.T) {
	mustPanic(t, func() { _, _ = addrZero.ResolveIPPort(t.Context(), "ip", addrFakeResolver) }, "addrZero.ResolveIPPort()")
}

func TestAddrHost(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
		want string
	}{
		{"IP4", addrIP4, addrIP4Host},
		{"IP4In6", addrIP4In6, addrIP4In6Host},
		{"IP4In6Zone", addrIP4In6Zone, addrIP4In6ZoneHost},
		{"IP6", addrIP6, addrIP6Host},
		{"Domain", addrDomain, addrDomainHost},
	} {
		t.Run(c.name, func(t *testing.T) {
			if host := c.addr.Host(); host != c.want {
				t.Errorf("%q.Host() = %q, want %q", c.addr, host, c.want)
			}
		})
	}
}

func TestAddrHostPanic(t *testing.T) {
	mustPanic(t, func() { _ = addrZero.Host() }, "addrZero.Host()")
}

var addrTextCases = [...]struct {
	name string
	addr Addr
	text string
}{
	{"Zero", addrZero, addrZeroString},
	{"IP4", addrIP4, addrIP4String},
	{"IP4In6", addrIP4In6, addrIP4In6String},
	{"IP4In6Zone", addrIP4In6Zone, addrIP4In6ZoneString},
	{"IP6", addrIP6, addrIP6String},
	{"Domain", addrDomain, addrDomainString},
}

func TestAddrString(t *testing.T) {
	for _, c := range addrTextCases {
		if s := c.addr.String(); s != c.text {
			t.Errorf("%q.String() = %q, want %q", c.addr, s, c.text)
		}
	}
}

func TestAddrMaxTextLen(t *testing.T) {
	for _, c := range [...]struct {
		name string
		addr Addr
		want int
	}{
		{"Zero", addrZero, 0},
		{"IP4", addrIP4, len("255.255.255.255:65535")},
		{"IP4In6", addrIP4In6, len("[::ffff:255.255.255.255]:65535")},
		{"IP4In6Zone", addrIP4In6Zone, len("[::ffff:255.255.255.255%lo]:65535")},
		{"IP6", addrIP6, len("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")},
		{"Domain", addrDomain, len(addrDomainHost + ":65535")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.addr.MaxTextLen(); got != c.want {
				t.Errorf("%q.MaxTextLen() = %d, want %d", c.addr, got, c.want)
			}
		})
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
			t.Fatalf("%q.AppendText() failed: %v", c.addr, err)
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
		{"IP4", addrIP4, 1},
		{"IP4In6", addrIP4In6, 1},
		{"IP4In6Zone", addrIP4In6Zone, 1},
		{"IP6", addrIP6, 1},
		{"Domain", addrDomain, 1},
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
			t.Fatalf("%q.MarshalText() failed: %v", c.addr, err)
		}
		if string(text) != c.text {
			t.Errorf("%q.MarshalText() = %q, want %q", c.addr, text, c.text)
		}

		var addr Addr
		if err = addr.UnmarshalText(text); err != nil {
			t.Fatalf("%q.UnmarshalText() failed: %v", text, err)
		}
		if addr != c.addr {
			t.Errorf("addr.UnmarshalText(%q) = %q, want %q", text, addr, c.addr)
		}
	}
}

func TestAddrMarshalTextAllocs(t *testing.T) {
	for _, c := range addrTextCases {
		t.Run(c.name, func(t *testing.T) {
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

func TestDomainIsValid(t *testing.T) {
	for _, c := range [...]struct {
		domain Domain
		want   bool
	}{
		{
			domain: Domain{},
			want:   false,
		},
		{
			domain: MustDomainFromString("example.com"),
			want:   true,
		},
		{
			domain: MustDomainFromString("example.com."),
			want:   true,
		},
	} {
		if got := c.domain.IsValid(); got != c.want {
			t.Errorf("%q.IsValid() = %v, want %v", c.domain, got, c.want)
		}
	}
}

var domainToTextCases = [...]struct {
	domain   Domain
	wantText string
}{
	{
		domain:   Domain{},
		wantText: "",
	},
	{
		domain:   MustDomainFromString("example.com"),
		wantText: "example.com",
	},
	{
		domain:   MustDomainFromString("example.com."),
		wantText: "example.com.",
	},
}

func TestDomainString(t *testing.T) {
	for _, c := range domainToTextCases {
		if s := c.domain.String(); s != c.wantText {
			t.Errorf("%q.String() = %q, want %q", c.domain, s, c.wantText)
		}
	}
}

func TestDomainAppendText(t *testing.T) {
	head := make([]byte, 64)
	rand.Read(head)

	b := make([]byte, 64, 128)
	_ = copy(b, head)

	for _, c := range domainToTextCases {
		full, err := c.domain.AppendText(b)
		if err != nil {
			t.Fatalf("%q.AppendText() failed: %v", c.domain, err)
		}
		if !bytes.Equal(full[:len(b)], head) {
			t.Errorf("%q.AppendText() modified b[:len(b)]", c.domain)
		}
		if tail := full[len(b):]; string(tail) != c.wantText {
			t.Errorf("%q.AppendText() = %q, want %q", c.domain, tail, c.wantText)
		}
	}
}

func TestDomainAppendTextAllocs(t *testing.T) {
	b := make([]byte, 0, 255)
	for _, c := range domainToTextCases {
		if n := testing.AllocsPerRun(10, func() {
			b, _ = c.domain.AppendText(b[:0])
		}); n > 0 {
			t.Errorf("%q.AppendText() allocs = %f, want 0", c.domain, n)
		}
	}
}

func TestDomainMarshalText(t *testing.T) {
	for _, c := range domainToTextCases {
		text, err := c.domain.MarshalText()
		if err != nil {
			t.Fatalf("%q.MarshalText() failed: %v", c.domain, err)
		}
		if string(text) != c.wantText {
			t.Errorf("%q.MarshalText() = %q, want %q", c.domain, text, c.wantText)
		}
	}
}

func TestDomainUnmarshalText(t *testing.T) {
	for _, c := range [...]struct {
		text       string
		wantDomain Domain
	}{
		{
			text:       "",
			wantDomain: Domain{},
		},
		{
			text:       "example.com",
			wantDomain: MustDomainFromString("example.com"),
		},
		{
			text:       "example.com.",
			wantDomain: MustDomainFromString("example.com."),
		},
		{
			text:       "ExAmPlE.CoM",
			wantDomain: MustDomainFromString("example.com"),
		},
		{
			text:       "eXaMpLe.cOm.",
			wantDomain: MustDomainFromString("example.com."),
		},
	} {
		var d Domain
		if err := d.UnmarshalText([]byte(c.text)); err != nil {
			t.Fatalf("%q.UnmarshalText() failed: %v", c.text, err)
		}
		if d != c.wantDomain {
			t.Errorf("%q.UnmarshalText() = %q, want %q", c.text, d, c.wantDomain)
		}
	}
}

func TestAddrFromDomainPortZeroDomain(t *testing.T) {
	if got := AddrFromDomainPort(Domain{}, 443); got != (Addr{}) {
		t.Errorf("AddrFromDomainPort(Domain{}, 443) = %q, want zero value", got)
	}
}

var addrFromDomainPortCases = [...]struct {
	name       string
	domain     string
	wantDomain Domain
	port       uint16
}{
	{
		name:       "Short=6",
		domain:     "aka.ms",
		wantDomain: MustDomainFromString("aka.ms"),
		port:       80,
	},
	{
		name:       "Medium=16",
		domain:     "www.example.com.",
		wantDomain: MustDomainFromString("www.example.com."),
		port:       443,
	},
	{
		name:       "LongUppercase=50",
		domain:     "WE.WRITE.EVERYTHING.WITH.CAPS.LOCK.ON.JUST.FOR.FUN",
		wantDomain: MustDomainFromString("WE.WRITE.EVERYTHING.WITH.CAPS.LOCK.ON.JUST.FOR.FUN"),
		port:       8080,
	},
	{
		name:       "CrazyLong=144",
		domain:     "each-label-is-up-to-63-bytes-long.the-higher-two-bits-of-the-length-byte-indicates-compression.oops-getting-real-close-to-that-limit.rfc1035.org",
		wantDomain: MustDomainFromString("each-label-is-up-to-63-bytes-long.the-higher-two-bits-of-the-length-byte-indicates-compression.oops-getting-real-close-to-that-limit.rfc1035.org"),
		port:       8443,
	},
}

func TestAddrFromDomainStringAndPort(t *testing.T) {
	for _, c := range addrFromDomainPortCases {
		addr, err := AddrFromDomainStringAndPort(c.domain, c.port)
		if err != nil {
			t.Errorf("AddrFromDomainStringAndPort(%q, %d) failed: %v", c.domain, c.port, err)
			continue
		}
		if got := addr.Domain(); got != c.wantDomain {
			t.Errorf("AddrFromDomainStringAndPort(%q, %d).Domain() = %q, want %q", c.domain, c.port, got, c.wantDomain)
		}
		if got := addr.Port(); got != c.port {
			t.Errorf("AddrFromDomainStringAndPort(%q, %d).Port() = %d, want %d", c.domain, c.port, got, c.port)
		}
	}
}

func TestAddrFromDomainBytesAndPort(t *testing.T) {
	for _, c := range addrFromDomainPortCases {
		addr, err := AddrFromDomainBytesAndPort([]byte(c.domain), c.port)
		if err != nil {
			t.Errorf("AddrFromDomainBytesAndPort(%q, %d) failed: %v", c.domain, c.port, err)
			continue
		}
		if got := addr.Domain(); got != c.wantDomain {
			t.Errorf("AddrFromDomainBytesAndPort(%q, %d).Domain() = %q, want %q", c.domain, c.port, got, c.wantDomain)
		}
		if got := addr.Port(); got != c.port {
			t.Errorf("AddrFromDomainBytesAndPort(%q, %d).Port() = %d, want %d", c.domain, c.port, got, c.port)
		}
	}
}

var addrFromDomainPortErrorCases = [...]struct {
	name   string
	domain string
	port   uint16
}{
	{"EmptyDomain", "", 443},
	{"LongDomain", strings.Repeat(" ", 256), 443},
	{"EmojiDomain", "😀.com", 443},
	{"PercentEncodedDomain", "exampl%65.com", 443},
}

func TestAddrFromDomainStringAndPortError(t *testing.T) {
	for _, c := range addrFromDomainPortErrorCases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AddrFromDomainStringAndPort(c.domain, c.port); err == nil {
				t.Errorf("AddrFromDomainStringAndPort(%q, %d) did not return error.", c.domain, c.port)
			}
		})
	}
}

func TestAddrFromDomainBytesAndPortError(t *testing.T) {
	for _, c := range addrFromDomainPortErrorCases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AddrFromDomainBytesAndPort([]byte(c.domain), c.port); err == nil {
				t.Errorf("AddrFromDomainBytesAndPort(%q, %d) did not return error.", c.domain, c.port)
			}
		})
	}
}

func TestAddrFromDomainStringAndPortAllocs(t *testing.T) {
	if testing.CoverMode() != "" {
		t.Skip("coverage mode breaks the compiler optimization this depends on")
	}
	for _, c := range addrFromDomainPortCases {
		if n := testing.AllocsPerRun(10, func() {
			_, _ = AddrFromDomainStringAndPort(c.domain, c.port)
		}); n > 0 {
			t.Errorf("AddrFromDomainStringAndPort(%q, %d) allocs = %f, want 0", c.domain, c.port, n)
		}
	}
}

func TestAddrFromDomainBytesAndPortAllocs(t *testing.T) {
	if testing.CoverMode() != "" {
		t.Skip("coverage mode breaks the compiler optimization this depends on")
	}
	for _, c := range addrFromDomainPortCases {
		if n := testing.AllocsPerRun(10, func() {
			buf := make([]byte, 0, 255)
			buf = append(buf, c.domain...)
			_, _ = AddrFromDomainBytesAndPort(buf, c.port)
		}); n > 0 {
			t.Errorf("AddrFromDomainBytesAndPort(%q, %d) allocs = %f, want 0", c.domain, c.port, n)
		}
	}
}

func BenchmarkDomainFromByteString(b *testing.B) {
	for _, c := range addrFromDomainPortCases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_, _ = DomainFromByteString(c.domain)
			}
		})
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
		{"IP4", addrIP4Host, addrIP4Port, addrIP4},
		{"IP4In6", addrIP4In6Host, addrIP4In6Port, addrIP4In6},
		{"IP4In6Zone", addrIP4In6ZoneHost, addrIP4In6ZonePort, addrIP4In6Zone},
		{"IP6", addrIP6Host, addrIP6Port, addrIP6},
		{"Domain", addrDomainHost, addrDomainPort, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := AddrFromHostPort(c.host, c.port)
			if err != nil {
				t.Fatal(err)
			}
			if addr != c.expectedAddr {
				t.Errorf("AddrFromHostPort(%q, %d) = %q, want %q", c.host, c.port, addr, c.expectedAddr)
			}
		})
	}
}

func TestAddrFromHostPortAllocs(t *testing.T) {
	// Currently we can only guarantee zero allocations for IP hosts.
	// For domain hosts, [netip.ParseAddr] allocates an error.
	// See https://github.com/golang/go/issues/76766.
	for _, c := range [...]struct {
		host string
		port uint16
	}{
		{addrIP4Host, addrIP4Port},
		{addrIP4In6Host, addrIP4In6Port},
		{addrIP4In6ZoneHost, addrIP4In6ZonePort},
		{addrIP6Host, addrIP6Port},
	} {
		if n := testing.AllocsPerRun(10, func() {
			_, _ = AddrFromHostPort(c.host, c.port)
		}); n > 0 {
			t.Errorf("AddrFromHostPort(%q, %d) allocs = %f, want 0", c.host, c.port, n)
		}
	}
}

func TestParseAddr(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		if _, err := ParseAddr(""); err == nil {
			t.Error("ParseAddr(\"\") did not return error.")
		}
	})

	for _, c := range [...]struct {
		name         string
		text         string
		expectedAddr Addr
	}{
		{"IP4", addrIP4String, addrIP4},
		{"IP4In6", addrIP4In6String, addrIP4In6},
		{"IP4In6Zone", addrIP4In6ZoneString, addrIP4In6Zone},
		{"IP6", addrIP6String, addrIP6},
		{"Domain", addrDomainString, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := ParseAddr(c.text)
			if err != nil {
				t.Fatal(err)
			}
			if addr != c.expectedAddr {
				t.Errorf("ParseAddr(%q) = %q, want %q", c.text, addr, c.expectedAddr)
			}
		})
	}
}

func TestParseAddrError(t *testing.T) {
	for _, c := range [...]struct {
		name string
		text string
	}{
		{"Empty", ""},
		{"EmptyHost", ":80"},
		{"EmptyPort", "localhost:"},
		{"PortService", "localhost:http"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAddr(c.text); err == nil {
				t.Errorf("ParseAddr(%q) did not return an error", c.text)
			}
		})
	}
}

func TestParseAddrAllocs(t *testing.T) {
	if n := testing.AllocsPerRun(10, func() {
		_, _ = ParseAddr(addrIP6String)
	}); n > 0 {
		t.Errorf("ParseAddr(%q) allocs = %f, want 0", addrIP6String, n)
	}
}

func TestAddrPortMappedEqual(t *testing.T) {
	for _, c := range []struct {
		a, b netip.AddrPort
		eq   bool
	}{
		{netip.AddrPort{}, netip.AddrPort{}, true},
		{netip.AddrPort{}, addrIP4AddrPort, false},
		{netip.AddrPort{}, addrIP4In6AddrPort, false},
		{netip.AddrPort{}, addrIP4In6ZoneAddrPort, false},
		{netip.AddrPort{}, addrIP6AddrPort, false},
		{addrIP4AddrPort, addrIP4AddrPort, true},
		{addrIP4AddrPort, addrIP4In6AddrPort, false},
		{addrIP4AddrPort, addrIP4In6ZoneAddrPort, false},
		{addrIP4AddrPort, addrIP6AddrPort, false},
		{addrIP4In6AddrPort, addrIP4In6AddrPort, true},
		{addrIP4In6AddrPort, addrIP4In6ZoneAddrPort, false},
		{addrIP4In6AddrPort, addrIP6AddrPort, false},
		{addrIP4In6ZoneAddrPort, addrIP4In6ZoneAddrPort, true},
		{addrIP4In6ZoneAddrPort, addrIP6AddrPort, false},
		{addrIP6AddrPort, addrIP6AddrPort, true},
		{netip.AddrPortFrom(addrIP4Addr.Next(), addrIP4Port), addrIP4AddrPort, false},
		{netip.AddrPortFrom(addrIP4Addr.Next(), addrIP4In6Port), addrIP4In6AddrPort, true},
		{netip.AddrPortFrom(addrIP4Addr.Next(), addrIP4In6ZonePort), netip.AddrPortFrom(addrIP4In6ZoneAddr.Prev(), addrIP4In6ZonePort), true},
	} {
		if eq := AddrPortMappedEqual(c.a, c.b); eq != c.eq {
			t.Errorf("AddrPortMappedEqual(%q, %q) = %t, want %t", c.a, c.b, eq, c.eq)
		}
	}
}

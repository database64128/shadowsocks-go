package conn

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
)

// Test IP address.
var (
	addrIP                = AddrFromIPPort(addrIPAddrPort)
	addrIPAddr            = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addrIPPort     uint16 = 1080
	addrIPAddrPort        = netip.AddrPortFrom(addrIPAddr, addrIPPort)
	addrIPHost            = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addrIPString          = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

// Test domain name.
var (
	addrDomain              = AddrFromDomainPort(addrDomainHost, addrDomainPort)
	addrDomainHost          = "example.com"
	addrDomainPort   uint16 = 443
	addrDomainString        = "example.com:443"
)

func TestAddrIsIP(t *testing.T) {
	if !addrIP.IsIP() {
		t.Error("addrIP.IsIP() returned false.")
	}

	if addrDomain.IsIP() {
		t.Error("addrDomain.IsIP() returned true.")
	}
}

func TestAddrIP(t *testing.T) {
	if addrIP.IP() != addrIPAddr {
		t.Errorf("addrIP.IP() returned %s, expected %s.", addrIP.IP(), addrIPAddr)
	}

	var netipAddrZeroValue netip.Addr
	if addrDomain.IP() != netipAddrZeroValue {
		t.Errorf("addrDomain.IP() returned %s, expected zero value.", addrDomain.IP())
	}
}

func TestAddrDomain(t *testing.T) {
	if addrIP.Domain() != "" {
		t.Errorf("addrIP.Domain() returned %s, expected empty string.", addrIP.Domain())
	}

	if addrDomain.Domain() != addrDomainHost {
		t.Errorf("addrDomain.Domain() returned %s, expected %s.", addrDomain.Domain(), addrDomainHost)
	}
}

func TestAddrPort(t *testing.T) {
	if addrIP.Port() != addrIPPort {
		t.Errorf("addrIP.Port() returned %d, expected %d.", addrIP.Port(), addrIPPort)
	}

	if addrDomain.Port() != addrDomainPort {
		t.Errorf("addrDomain.Port() returned %d, expected %d.", addrDomain.Port(), addrDomainPort)
	}
}

func TestAddrIPPort(t *testing.T) {
	if addrIP.IPPort() != addrIPAddrPort {
		t.Errorf("addrIP.IPPort() returned %s, expected %s.", addrIP.IPPort(), addrIPAddrPort)
	}

	addrPort := netip.AddrPortFrom(netip.Addr{}, addrDomainPort)
	if addrDomain.IPPort() != addrPort {
		t.Errorf("addrDomain.IPPort() returned %s, expected zero-value address and %d.", addrDomain.IPPort(), addrDomainPort)
	}
}

func TestAddrResolveIP(t *testing.T) {
	ip, err := addrIP.ResolveIP(false)
	if err != nil {
		t.Errorf("addrIP.ResolveIP(false) returned error: %s.", err)
	}
	if ip != addrIPAddr {
		t.Errorf("addrIP.ResolveIP(false) returned %s, expected %s.", ip, addrIPAddr)
	}

	ip, err = addrIP.ResolveIP(true)
	if err != nil {
		t.Errorf("addrIP.ResolveIP(true) returned error: %s.", err)
	}
	if ip != addrIPAddr {
		t.Errorf("addrIP.ResolveIP(true) returned %s, expected %s.", ip, addrIPAddr)
	}

	ip, err = addrDomain.ResolveIP(false)
	if err != nil {
		t.Errorf("addrDomain.ResolveIP(false) returned error: %s.", err)
	}
	if !ip.Is4() && !ip.Is4In6() {
		t.Errorf("addrDomain.ResolveIP(false) returned %s, expected IPv4 or IPv4-mapped IPv6 address.", ip)
	}

	ip, err = addrDomain.ResolveIP(true)
	if err != nil {
		t.Errorf("addrDomain.ResolveIP(true) returned error: %s.", err)
	}
	if ip.Is4() || ip.Is4In6() {
		t.Errorf("addrDomain.ResolveIP(true) returned %s, expected IPv6 address.", ip)
	}
}

func TestAddrResolveIPPort(t *testing.T) {
	ipPort, err := addrIP.ResolveIPPort(false)
	if err != nil {
		t.Errorf("addrIP.ResolveIPPort(false) returned error: %s.", err)
	}
	if ipPort != addrIPAddrPort {
		t.Errorf("addrIP.ResolveIPPort(false) returned %s, expected %s.", ipPort, addrIPAddrPort)
	}

	ipPort, err = addrIP.ResolveIPPort(true)
	if err != nil {
		t.Errorf("addrIP.ResolveIPPort(true) returned error: %s.", err)
	}
	if ipPort != addrIPAddrPort {
		t.Errorf("addrIP.ResolveIPPort(true) returned %s, expected %s.", ipPort, addrIPAddrPort)
	}

	ipPort, err = addrDomain.ResolveIPPort(false)
	if err != nil {
		t.Errorf("addrDomain.ResolveIPPort(false) returned error: %s.", err)
	}
	if ip := ipPort.Addr(); !ip.Is4() && !ip.Is4In6() {
		t.Errorf("addrDomain.ResolveIPPort(false) returned %s, expected IPv4 or IPv4-mapped IPv6 address.", ipPort)
	}
	if ipPort.Port() != addrDomainPort {
		t.Errorf("addrDomain.ResolveIPPort(false) returned %s, expected port %d.", ipPort, addrDomainPort)
	}

	ipPort, err = addrDomain.ResolveIPPort(true)
	if err != nil {
		t.Errorf("addrDomain.ResolveIPPort(true) returned error: %s.", err)
	}
	if ip := ipPort.Addr(); ip.Is4() || ip.Is4In6() {
		t.Errorf("addrDomain.ResolveIPPort(true) returned %s, expected IPv6 address.", ipPort)
	}
	if ipPort.Port() != addrDomainPort {
		t.Errorf("addrDomain.ResolveIPPort(true) returned %s, expected port %d.", ipPort, addrDomainPort)
	}
}

func TestAddrHost(t *testing.T) {
	if addrIP.Host() != addrIPHost {
		t.Errorf("addrIP.Host() returned %s, expected %s.", addrIP.Host(), addrIPHost)
	}

	if addrDomain.Host() != addrDomainHost {
		t.Errorf("addrDomain.Host() returned %s, expected %s.", addrDomain.Host(), addrDomainHost)
	}
}

func TestAddrString(t *testing.T) {
	if addrIP.String() != addrIPString {
		t.Errorf("addrIP.String() returned %s, expected %s.", addrIP.String(), addrIPString)
	}

	if addrDomain.String() != addrDomainString {
		t.Errorf("addrDomain.String() returned %s, expected %s.", addrDomain.String(), addrDomainString)
	}
}

func TestAddrAppendTo(t *testing.T) {
	head := make([]byte, 64)
	_, err := rand.Read(head)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 0, 128)
	b = append(b, head...)
	bHead := b

	b = addrIP.AppendTo(bHead)
	if !bytes.Equal(bHead, head) {
		t.Error("addrIP.AppendTo() returned modified head.")
	}
	if string(b[64:]) != addrIPString {
		t.Errorf("addrIP.AppendTo() returned %s, expected %s.", string(b[64:]), addrIPString)
	}

	b = addrDomain.AppendTo(bHead)
	if !bytes.Equal(bHead, head) {
		t.Error("addrDomain.AppendTo() returned modified head.")
	}
	if string(b[64:]) != addrDomainString {
		t.Errorf("addrDomain.AppendTo() returned %s, expected %s.", string(b[64:]), addrDomainString)
	}
}

func TestAddrMarshalAndUnmarshalText(t *testing.T) {
	text, err := addrIP.MarshalText()
	if err != nil {
		t.Errorf("addrIP.MarshalText() returned error: %s.", err)
	}
	if string(text) != addrIPString {
		t.Errorf("addrIP.MarshalText() returned %s, expected %s.", text, addrIPString)
	}

	var addrUnmarshaled Addr
	err = addrUnmarshaled.UnmarshalText(text)
	if err != nil {
		t.Errorf("addrIP.UnmarshalText() returned error: %s.", err)
	}
	if addrUnmarshaled != addrIP {
		t.Errorf("addrIP.UnmarshalText() returned %s, expected %s.", addrUnmarshaled, addrIP)
	}

	text, err = addrDomain.MarshalText()
	if err != nil {
		t.Errorf("addrDomain.MarshalText() returned error: %s.", err)
	}
	if string(text) != addrDomainString {
		t.Errorf("addrDomain.MarshalText() returned %s, expected %s.", text, addrDomainString)
	}

	err = addrUnmarshaled.UnmarshalText(text)
	if err != nil {
		t.Errorf("addrDomain.UnmarshalText() returned error: %s.", err)
	}
	if addrUnmarshaled != addrDomain {
		t.Errorf("addrDomain.UnmarshalText() returned %s, expected %s.", addrUnmarshaled, addrDomain)
	}
}

func TestAddrFromHostPort(t *testing.T) {
	addrFromHostPort := AddrFromHostPort(addrIPHost, addrIPPort)
	if addrFromHostPort != addrIP {
		t.Errorf("AddrFromHostPort() returned %s, expected %s.", addrFromHostPort, addrIP)
	}

	addrFromHostPort = AddrFromHostPort(addrDomainHost, addrDomainPort)
	if addrFromHostPort != addrDomain {
		t.Errorf("AddrFromHostPort() returned %s, expected %s.", addrFromHostPort, addrDomain)
	}
}

func TestAddrParsing(t *testing.T) {
	addrParsed, err := ParseAddr(addrIPString)
	if err != nil {
		t.Errorf("ParseAddr() returned error: %s.", err)
	}
	if addrParsed != addrIP {
		t.Errorf("ParseAddr() returned %s, expected %s.", addrParsed, addrIP)
	}

	addrParsed, err = ParseAddr(addrDomainString)
	if err != nil {
		t.Errorf("ParseAddr() returned error: %s.", err)
	}
	if addrParsed != addrDomain {
		t.Errorf("ParseAddr() returned %s, expected %s.", addrParsed, addrDomain)
	}
}

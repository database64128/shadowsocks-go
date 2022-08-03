package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/magic"
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
//
// Do not convert []byte directly to Addr. Use one of the following functions
// that returns an Addr.
type Addr []byte

// IsDomain returns whether the address is a domain name.
func (a Addr) IsDomain() bool {
	return a[0] == AtypDomainName
}

// IsIPv4 returns whether the address is an IPv4 address.
func (a Addr) IsIPv4() bool {
	return a[0] == AtypIPv4
}

// IsIPv6 returns whether the address is an IPv6 address.
func (a Addr) IsIPv6() bool {
	return a[0] == AtypIPv6
}

// Host returns the host name of the SOCKS address.
func (a Addr) Host() string {
	switch a[0] {
	case AtypDomainName:
		domainLen := int(a[1])
		return string(a[2 : 2+domainLen])
	case AtypIPv4:
		ip4 := (*[4]byte)(a[1:])
		return netip.AddrFrom4(*ip4).String()
	case AtypIPv6:
		ip6 := (*[16]byte)(a[1:])
		return netip.AddrFrom16(*ip6).String()
	default:
		panic(fmt.Errorf("unknown atyp %d", a[0]))
	}
}

// Addr converts the SOCKS address to a netip.Addr.
// An error is returned only when the SOCKS address is a domain name
// and name resolution fails.
func (a Addr) Addr(preferIPv6 bool) (netip.Addr, error) {
	switch a[0] {
	case AtypDomainName:
		domainLen := int(a[1])
		domain := string(a[2 : 2+domainLen])
		return conn.ResolveAddr(domain, preferIPv6)
	case AtypIPv4:
		ip4 := (*[4]byte)(a[1:])
		return netip.AddrFrom4(*ip4), nil
	case AtypIPv6:
		ip6 := (*[16]byte)(a[1:])
		return netip.AddrFrom16(*ip6), nil
	default:
		panic(fmt.Errorf("unknown atyp %d", a[0]))
	}
}

// Port returns the port number of the SOCKS address.
func (a Addr) Port() uint16 {
	switch a[0] {
	case AtypDomainName:
		domainLen := int(a[1])
		return binary.BigEndian.Uint16(a[2+domainLen:])
	case AtypIPv4:
		return binary.BigEndian.Uint16(a[1+4:])
	case AtypIPv6:
		return binary.BigEndian.Uint16(a[1+16:])
	default:
		panic(fmt.Errorf("unknown atyp %d", a[0]))
	}
}

// AddrPort converts the SOCKS address to netip.AddrPort.
// An error is returned only when the SOCKS address is a domain name
// and name resolution fails.
func (a Addr) AddrPort(preferIPv6 bool) (netip.AddrPort, error) {
	switch a[0] {
	case AtypDomainName:
		domainLen := int(a[1])
		domain := string(a[2 : 2+domainLen])
		addr, err := conn.ResolveAddr(domain, preferIPv6)
		port := binary.BigEndian.Uint16(a[2+domainLen:])
		return netip.AddrPortFrom(addr, port), err
	case AtypIPv4:
		ip4 := (*[4]byte)(a[1:])
		addr := netip.AddrFrom4(*ip4)
		port := binary.BigEndian.Uint16(a[1+4:])
		return netip.AddrPortFrom(addr, port), nil
	case AtypIPv6:
		ip6 := (*[16]byte)(a[1:])
		addr := netip.AddrFrom16(*ip6)
		port := binary.BigEndian.Uint16(a[1+16:])
		return netip.AddrPortFrom(addr, port), nil
	default:
		panic(fmt.Errorf("unknown atyp %d", a[0]))
	}
}

// String returns the string representation of the SOCKS address.
func (a Addr) String() string {
	switch a[0] {
	case AtypDomainName:
		domainLen := int(a[1])
		domain := string(a[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(a[2+domainLen:])
		return fmt.Sprintf("%s:%d", domain, port)
	case AtypIPv4, AtypIPv6:
		addrPort, _ := a.AddrPort(true)
		return addrPort.String()
	default:
		panic(fmt.Errorf("unknown atyp %d", a[0]))
	}
}

// MarshalText implements the encoding.TextMarshaler interface.
func (a Addr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (a *Addr) UnmarshalText(text []byte) error {
	addr, err := ParseAddr(string(text))
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// AppendAddrFromAddrPort appends the netip.AddrPort to the buffer in the SOCKS address format.
//
// If the address is an IPv4-mapped IPv6 address, it is converted to an IPv4 address.
func AppendAddrFromAddrPort(b []byte, addrPort netip.AddrPort) []byte {
	var ret, out []byte
	ip := addrPort.Addr()
	switch {
	case ip.Is4() || ip.Is4In6():
		ret, out = magic.SliceForAppend(b, 1+4+2)
		out[0] = AtypIPv4
		ip4 := ip.As4()
		copy(out[1:], ip4[:])
	case ip.Is6() || !ip.IsValid():
		ret, out = magic.SliceForAppend(b, 1+16+2)
		out[0] = AtypIPv6
		ip6 := ip.As16()
		copy(out[1:], ip6[:])
	}
	binary.BigEndian.PutUint16(out[len(out)-2:], addrPort.Port())
	return ret
}

// AppendAddrFromConnAddr appends the address to the buffer in the SOCKS address format.
//
// If the address is an IPv4-mapped IPv6 address, it is converted to an IPv4 address.
func AppendAddrFromConnAddr(b []byte, addr conn.Addr) ([]byte, error) {
	if addr.IsIP() {
		return AppendAddrFromAddrPort(b, addr.IPPort()), nil
	}

	domain := addr.Domain()
	if len(domain) > 255 {
		return nil, fmt.Errorf("length of domain %s exceeds 255", domain)
	}

	ret, out := magic.SliceForAppend(b, 1+1+len(domain)+2)
	out[0] = AtypDomainName
	out[1] = byte(len(domain))
	copy(out[2:], domain)

	port := addr.Port()
	binary.BigEndian.PutUint16(out[1+1+len(domain):], port)

	return ret, nil
}

// AddrFromAddrPort creates a SOCKS address from a netip.AddrPort.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func AddrFromAddrPort(addrPort netip.AddrPort) Addr {
	var b []byte
	ip := addrPort.Addr()
	switch {
	case ip.Is4() || ip.Is4In6():
		b = make([]byte, 1+4+2)
		b[0] = AtypIPv4
		ip4 := ip.As4()
		copy(b[1:], ip4[:])
	case ip.Is6() || !ip.IsValid():
		b = make([]byte, 1+16+2)
		b[0] = AtypIPv6
		ip6 := ip.As16()
		copy(b[1:], ip6[:])
	}
	binary.BigEndian.PutUint16(b[len(b)-2:], addrPort.Port())
	return b
}

// AppendFromHostPort parses a host string, combines it with a port number
// into a SOCKS address and appends it to the buffer.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func AppendFromHostPort(b []byte, host string, port uint16) ([]byte, error) {
	if host == "" {
		host = "::"
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return AppendAddrFromAddrPort(b, netip.AddrPortFrom(ip, port)), nil
	}

	if len(host) > 255 {
		return nil, fmt.Errorf("host is too long: %d, must not be greater than 255", len(host))
	}

	ret, out := magic.SliceForAppend(b, 1+1+len(host)+2)
	out[0] = AtypDomainName
	out[1] = byte(len(host))
	copy(out[2:], host)
	binary.BigEndian.PutUint16(out[len(out)-2:], port)
	return ret, nil
}

// ParseHostPort parses a host string and combines it with a port number
// into a SOCKS address.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func ParseHostPort(host string, port uint16) (Addr, error) {
	if host == "" {
		host = "::"
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return AddrFromAddrPort(netip.AddrPortFrom(ip, port)), nil
	}

	if len(host) > 255 {
		return nil, fmt.Errorf("host is too long: %d, must not be greater than 255", len(host))
	}

	b := make([]byte, 1+1+len(host)+2)
	b[0] = AtypDomainName
	b[1] = byte(len(host))
	copy(b[2:], host)
	binary.BigEndian.PutUint16(b[len(b)-2:], port)
	return b, nil
}

// AppendFromString parses an address string into a SOCKS address
// and appends it to the buffer.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func AppendFromString(b []byte, s string) (ret []byte, host string, port uint16, err error) {
	host, portString, err := net.SplitHostPort(s)
	if err != nil {
		err = fmt.Errorf("failed to split host:port: %w", err)
		return
	}

	portNumber, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		err = fmt.Errorf("failed to parse port string: %w", err)
		return
	}
	port = uint16(portNumber)

	ret, err = AppendFromHostPort(b, host, port)
	return
}

// ParseAddr parses an address string into a SOCKS address.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
func ParseAddr(s string) (Addr, error) {
	host, portString, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("failed to split host:port: %w", err)
	}

	portNumber, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port string: %w", err)
	}
	port := uint16(portNumber)

	return ParseHostPort(host, port)
}

// AppendFromReader reads just enough bytes from r to get a valid Addr
// and appends it to the buffer.
func AppendFromReader(b []byte, r io.Reader) ([]byte, error) {
	ret, out := magic.SliceForAppend(b, 2)

	// Read ATYP and an extra byte.
	_, err := io.ReadFull(r, out)
	if err != nil {
		return nil, err
	}

	var addrLen int

	switch out[0] {
	case AtypDomainName:
		addrLen = 1 + 1 + int(out[1]) + 2
	case AtypIPv4:
		addrLen = 1 + 4 + 2
	case AtypIPv6:
		addrLen = 1 + 16 + 2
	default:
		return nil, fmt.Errorf("unknown atyp %d", out[0])
	}

	ret, out = magic.SliceForAppend(ret[:len(b)+2], addrLen-2)
	_, err = io.ReadFull(r, out)
	return ret, err
}

// ConnAddrFromReader reads a SOCKS address from r and returns the converted conn.Addr.
func ConnAddrFromReader(r io.Reader) (conn.Addr, error) {
	b := make([]byte, 2)

	// Read ATYP and an extra byte.
	_, err := io.ReadFull(r, b)
	if err != nil {
		return conn.Addr{}, err
	}

	switch b[0] {
	case AtypDomainName:
		b1 := make([]byte, int(b[1])+2)
		_, err = io.ReadFull(r, b1)
		if err != nil {
			return conn.Addr{}, err
		}
		b2 := b1[:b[1]:b[1]]
		domain := *(*string)(unsafe.Pointer(&b2))
		port := binary.BigEndian.Uint16(b1[b[1]:])
		return conn.AddrFromDomainPort(domain, port), nil

	case AtypIPv4:
		b1 := make([]byte, 4+2)
		b1[0] = b[1]
		_, err = io.ReadFull(r, b1[1:])
		if err != nil {
			return conn.Addr{}, err
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b1))
		port := binary.BigEndian.Uint16(b1[4:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), nil

	case AtypIPv6:
		b1 := make([]byte, 16+2)
		b1[0] = b[1]
		_, err = io.ReadFull(r, b1[1:])
		if err != nil {
			return conn.Addr{}, err
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b1))
		port := binary.BigEndian.Uint16(b1[16:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), nil

	default:
		return conn.Addr{}, fmt.Errorf("invalid ATYP: %d", b[0])
	}
}

// AddrFromReader allocates and reads a SOCKS address from an io.Reader.
//
// To avoid allocations, call AppendFromReader directly.
func AddrFromReader(r io.Reader) (Addr, error) {
	b := make([]byte, 0, MaxAddrLen)
	return AppendFromReader(b, r)
}

// SplitAddr slices a SOCKS address from the beginning of b and returns the SOCKS address,
// or an error if no valid SOCKS address is found.
func SplitAddr(b []byte) (Addr, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("addr length too short: %d", len(b))
	}

	var addrLen int

	switch b[0] {
	case AtypDomainName:
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + 4 + 2
	case AtypIPv6:
		addrLen = 1 + 16 + 2
	default:
		return nil, fmt.Errorf("unknown atyp %d", b[0])
	}

	if len(b) < addrLen {
		return nil, fmt.Errorf("addr length %d is too short for atyp %d", len(b), b[0])
	}

	return b[:addrLen], nil
}

// ConnAddrFromSlice slices a SOCKS address from the beginning of b and returns the converted conn.Addr.
func ConnAddrFromSlice(b []byte) (conn.Addr, error) {
	if len(b) < 2 {
		return conn.Addr{}, fmt.Errorf("addr length too short: %d", len(b))
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 1+1+int(b[1])+2 {
			return conn.Addr{}, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		domain := string(b[2 : 2+int(b[1])])
		port := binary.BigEndian.Uint16(b[2+int(b[1]):])
		return conn.AddrFromDomainPort(domain, port), nil

	case AtypIPv4:
		if len(b) < 1+4+2 {
			return conn.Addr{}, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:5]))
		port := binary.BigEndian.Uint16(b[5:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return conn.Addr{}, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:17]))
		port := binary.BigEndian.Uint16(b[17:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), nil

	default:
		return conn.Addr{}, fmt.Errorf("invalid ATYP: %d", b[0])
	}
}

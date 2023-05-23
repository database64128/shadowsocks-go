package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/slices"
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

const (
	// IPv4AddrLen is the size of an IPv4 SOCKS address in bytes.
	IPv4AddrLen = 1 + 4 + 2

	// IPv6AddrLen is the size of an IPv6 SOCKS address in bytes.
	IPv6AddrLen = 1 + 16 + 2

	// MaxAddrLen is the maximum size of a SOCKS address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2
)

var (
	// IPv4UnspecifiedAddr represents 0.0.0.0:0.
	IPv4UnspecifiedAddr = [IPv4AddrLen]byte{AtypIPv4}

	// IPv6UnspecifiedAddr represents [::]:0.
	IPv6UnspecifiedAddr = [IPv6AddrLen]byte{AtypIPv6}
)

// AppendAddrFromAddrPort appends the netip.AddrPort to the buffer in the SOCKS address format.
//
// If the address is an IPv4-mapped IPv6 address, it is converted to an IPv4 address.
func AppendAddrFromAddrPort(b []byte, addrPort netip.AddrPort) []byte {
	var ret, out []byte
	ip := addrPort.Addr()
	switch {
	case ip.Is4() || ip.Is4In6():
		ret, out = slices.Extend(b, 1+4+2)
		out[0] = AtypIPv4
		*(*[4]byte)(out[1:]) = ip.As4()
	default:
		ret, out = slices.Extend(b, 1+16+2)
		out[0] = AtypIPv6
		*(*[16]byte)(out[1:]) = ip.As16()
	}
	binary.BigEndian.PutUint16(out[len(out)-2:], addrPort.Port())
	return ret
}

// WriteAddrFromAddrPort writes the netip.AddrPort to the buffer in the SOCKS address format
// and returns the number of bytes written.
//
// If the address is an IPv4-mapped IPv6 address, it is converted to an IPv4 address.
//
// This function does not check whether b has sufficient space for the address.
// The caller may call [LengthOfAddrFromAddrPort] to get the required length.
func WriteAddrFromAddrPort(b []byte, addrPort netip.AddrPort) (n int) {
	ip := addrPort.Addr()
	switch {
	case ip.Is4() || ip.Is4In6():
		b[0] = AtypIPv4
		*(*[4]byte)(b[1:]) = ip.As4()
		n = 1 + 4 + 2
	default:
		b[0] = AtypIPv6
		*(*[16]byte)(b[1:]) = ip.As16()
		n = 1 + 16 + 2
	}
	binary.BigEndian.PutUint16(b[n-2:], addrPort.Port())
	return
}

// LengthOfAddrFromAddrPort returns the length of a SOCKS address converted from the netip.AddrPort.
func LengthOfAddrFromAddrPort(addrPort netip.AddrPort) int {
	if ip := addrPort.Addr(); ip.Is4() || ip.Is4In6() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

// AppendAddrFromConnAddr appends the address to the buffer in the SOCKS address format.
//
// - Zero value address is treated as 0.0.0.0:0.
// - IPv4-mapped IPv6 address is converted to the equivalent IPv4 address.
func AppendAddrFromConnAddr(b []byte, addr conn.Addr) []byte {
	if !addr.IsValid() {
		return AppendAddrFromAddrPort(b, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	}

	if addr.IsIP() {
		return AppendAddrFromAddrPort(b, addr.IPPort())
	}

	domain := addr.Domain()
	ret, out := slices.Extend(b, 1+1+len(domain)+2)
	out[0] = AtypDomainName
	out[1] = byte(len(domain))
	copy(out[2:], domain)

	port := addr.Port()
	binary.BigEndian.PutUint16(out[1+1+len(domain):], port)

	return ret
}

// WriteAddrFromConnAddr writes the address to the buffer in the SOCKS address format
// and returns the number of bytes written.
//
// - Zero value address is treated as 0.0.0.0:0.
// - IPv4-mapped IPv6 address is converted to the equivalent IPv4 address.
//
// This function does not check whether b has sufficient space for the address.
// The caller may call [LengthOfAddrFromConnAddr] to get the required length.
func WriteAddrFromConnAddr(b []byte, addr conn.Addr) int {
	if !addr.IsValid() {
		return WriteAddrFromAddrPort(b, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	}

	if addr.IsIP() {
		return WriteAddrFromAddrPort(b, addr.IPPort())
	}

	domain := addr.Domain()
	b[0] = AtypDomainName
	b[1] = byte(len(domain))
	copy(b[2:], domain)

	port := addr.Port()
	binary.BigEndian.PutUint16(b[1+1+len(domain):], port)

	return 1 + 1 + len(domain) + 2
}

// LengthOfAddrFromConnAddr returns the length of a SOCKS address converted from the conn.Addr.
//
// - Zero value address is treated as 0.0.0.0:0.
// - IPv4-mapped IPv6 address is treated as the equivalent IPv4 address.
func LengthOfAddrFromConnAddr(addr conn.Addr) int {
	if !addr.IsValid() {
		return 1 + 4 + 2
	}
	if addr.IsIP() {
		return LengthOfAddrFromAddrPort(addr.IPPort())
	}
	domain := addr.Domain()
	return 1 + 1 + len(domain) + 2
}

// AppendFromReader reads just enough bytes from r to get a valid Addr
// and appends it to the buffer.
func AppendFromReader(b []byte, r io.Reader) ([]byte, error) {
	ret, out := slices.Extend(b, 2)

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

	ret, out = slices.Extend(ret, addrLen-2)
	_, err = io.ReadFull(r, out)
	return ret, err
}

// AddrFromReader allocates and reads a SOCKS address from an io.Reader.
//
// To avoid allocations, call AppendFromReader directly.
func AddrFromReader(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, MaxAddrLen)
	return AppendFromReader(b, r)
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
		return conn.AddrFromDomainPort(domain, port)

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

var errDomain = errors.New("addr is a domain")

// AddrPortFromSlice slices a SOCKS address from the beginning of b and returns the converted netip.AddrPort
// and the length of the SOCKS address.
func AddrPortFromSlice(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 1+4+2 {
		return netip.AddrPort{}, 0, fmt.Errorf("addr length too short: %d", len(b))
	}

	switch b[0] {
	case AtypIPv4:
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return netip.AddrPortFrom(ip, port), 1 + 4 + 2, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return netip.AddrPortFrom(ip, port), 1 + 16 + 2, nil

	case AtypDomainName:
		return netip.AddrPort{}, 0, errDomain

	default:
		return netip.AddrPort{}, 0, fmt.Errorf("invalid ATYP: %d", b[0])
	}
}

// ConnAddrFromSlice slices a SOCKS address from the beginning of b and returns the converted conn.Addr
// and the length of the SOCKS address.
func ConnAddrFromSlice(b []byte) (conn.Addr, int, error) {
	if len(b) < 2 {
		return conn.Addr{}, 0, fmt.Errorf("addr length too short: %d", len(b))
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 1+1+int(b[1])+2 {
			return conn.Addr{}, 0, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		domain := string(b[2 : 2+int(b[1])])
		port := binary.BigEndian.Uint16(b[2+int(b[1]):])
		addr, err := conn.AddrFromDomainPort(domain, port)
		return addr, 2 + int(b[1]) + 2, err

	case AtypIPv4:
		if len(b) < 1+4+2 {
			return conn.Addr{}, 0, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), 1 + 4 + 2, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return conn.Addr{}, 0, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), 1 + 16 + 2, nil

	default:
		return conn.Addr{}, 0, fmt.Errorf("invalid ATYP: %d", b[0])
	}
}

// ConnAddrFromSliceWithDomainCache is like [ConnAddrFromSlice] but uses a domain cache to minimize string allocations.
// The returned string is the updated domain cache.
func ConnAddrFromSliceWithDomainCache(b []byte, cachedDomain string) (conn.Addr, int, string, error) {
	if len(b) < 2 {
		return conn.Addr{}, 0, cachedDomain, fmt.Errorf("addr length too short: %d", len(b))
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 1+1+int(b[1])+2 {
			return conn.Addr{}, 0, cachedDomain, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		domain := b[2 : 2+int(b[1])]
		if cachedDomain != string(domain) { // Hopefully the compiler will optimize the string allocation away.
			cachedDomain = string(domain)
		}
		port := binary.BigEndian.Uint16(b[2+int(b[1]):])
		addr, err := conn.AddrFromDomainPort(cachedDomain, port)
		return addr, 2 + int(b[1]) + 2, cachedDomain, err

	case AtypIPv4:
		if len(b) < 1+4+2 {
			return conn.Addr{}, 0, cachedDomain, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1 : 1+4]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), 1 + 4 + 2, cachedDomain, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return conn.Addr{}, 0, cachedDomain, fmt.Errorf("addr length %d is too short for ATYP %d", len(b), b[0])
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1 : 1+16]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return conn.AddrFromIPPort(netip.AddrPortFrom(ip, port)), 1 + 16 + 2, cachedDomain, nil

	default:
		return conn.Addr{}, 0, cachedDomain, fmt.Errorf("invalid ATYP: %d", b[0])
	}
}

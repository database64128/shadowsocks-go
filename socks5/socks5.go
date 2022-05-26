package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/database64128/shadowsocks-go/conn"
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

// SOCKS errors as defined in RFC 1928 section 6.
const (
	Succeeded               = 0
	ErrGeneralFailure       = 1
	ErrConnectionNotAllowed = 2
	ErrNetworkUnreachable   = 3
	ErrHostUnreachable      = 4
	ErrConnectionRefused    = 5
	ErrTTLExpired           = 6
	ErrCommandNotSupported  = 7
	ErrAddressNotSupported  = 8
)

const (
	SocksAddressIPv4Length = 1 + net.IPv4len + 2
	SocksAddressIPv6Length = 1 + net.IPv6len + 2

	// MaxAddrLen is the maximum size of SOCKS address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2
)

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
//
// Do not convert []byte directly to Addr. Use one of the following functions
// that returns an Addr.
type Addr []byte

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
		panic(fmt.Errorf("unknown atyp %v", a[0]))
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
		panic(fmt.Errorf("unknown atyp %v", a[0]))
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
		panic(fmt.Errorf("unknown atyp %v", a[0]))
	}
}

// WriteAddrPortAsSocksAddr converts a netip.AddrPort into a SOCKS address
// and stores it in the buffer.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
//
// No buffer length checks are performed.
// Make sure the buffer can hold the socks address.
func WriteAddrPortAsSocksAddr(b []byte, addrPort netip.AddrPort) (n int) {
	ip := addrPort.Addr()
	switch {
	case ip.Is4() || ip.Is4In6():
		b[n] = AtypIPv4
		n++
		ip4 := ip.As4()
		n += copy(b[n:], ip4[:])
	case ip.Is6():
		b[n] = AtypIPv6
		n++
		ip6 := ip.As16()
		n += copy(b[n:], ip6[:])
	}

	binary.BigEndian.PutUint16(b[n:], addrPort.Port())
	n += 2
	return
}

// AddrFromAddrPort creates a SOCKS address from a netip.AddrPort.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
//
// To avoid allocations, call WriteAddrPortAsSocksAddr directly.
func AddrFromAddrPort(addrPort netip.AddrPort) Addr {
	b := make([]byte, MaxAddrLen)
	n := WriteAddrPortAsSocksAddr(b, addrPort)
	return b[:n]
}

// WriteStringAsSocksAddr parses an address string into a SOCKS address
// and stores it in the destination slice.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
//
// The destination slice must be big enough to hold the SOCKS address.
// Otherwise, this function might panic.
func WriteStringAsSocksAddr(dst []byte, s string) (n int, host string, port int, err error) {
	host, portString, err := net.SplitHostPort(s)
	if err != nil {
		err = fmt.Errorf("failed to split host:port: %w", err)
		return
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		switch {
		case ip.Is4() || ip.Is4In6():
			dst[n] = AtypIPv4
			n++
			ip4 := ip.As4()
			n += copy(dst[n:], ip4[:])
		case ip.Is6():
			dst[n] = AtypIPv6
			n++
			ip6 := ip.As16()
			n += copy(dst[n:], ip6[:])
		}
	} else {
		if len(host) > 255 {
			err = fmt.Errorf("host is too long: %d, must not be greater than 255", len(host))
			return
		}
		dst[n] = AtypDomainName
		n++
		dst[n] = byte(len(host))
		n++
		n += copy(dst[n:], host)
	}

	portnum, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		err = fmt.Errorf("failed to parse port string: %w", err)
		return
	}
	binary.BigEndian.PutUint16(dst[n:], uint16(portnum))
	n += 2
	port = int(portnum)

	return
}

// ParseAddr parses an address string into a SOCKS address.
//
// IPv4-mapped IPv6 addresses are converted to IPv4 addresses.
//
// To avoid allocations, call WriteStringAsSocksAddr directly.
func ParseAddr(s string) (Addr, error) {
	dst := make([]byte, MaxAddrLen)
	n, _, _, err := WriteStringAsSocksAddr(dst, s)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// ReadAddr reads just enough bytes from r to get a valid Addr.
//
// The destination slice must be big enough to hold the socks address.
// Otherwise, this function might panic.
func ReadAddr(dst []byte, r io.Reader) (n int, err error) {
	n, err = io.ReadFull(r, dst[:1]) // read 1st byte for address type
	if err != nil {
		return
	}

	switch dst[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, dst[1:2]) // read 2nd byte for domain length
		if err != nil {
			return
		}
		domainLen := int(dst[1])
		n += 1 + domainLen + 2
		_, err = io.ReadFull(r, dst[2:n])
		return
	case AtypIPv4:
		n += net.IPv4len + 2
		_, err = io.ReadFull(r, dst[1:n])
		return
	case AtypIPv6:
		n += net.IPv6len + 2
		_, err = io.ReadFull(r, dst[1:n])
		return
	}

	err = fmt.Errorf("unknown atyp %v", dst[0])
	return
}

// AddrFromReader allocates and reads a socks address from an io.Reader.
//
// To avoid allocations, call ReadAddr directly.
func AddrFromReader(r io.Reader) (Addr, error) {
	dst := make([]byte, MaxAddrLen)
	n, err := ReadAddr(dst, r)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// SplitAddr slices a SOCKS address from the beginning of b and returns the SOCKS address,
// or an error if no valid SOCKS address is found.
func SplitAddr(b []byte) (Addr, error) {
	addrLen := 1
	if len(b) < addrLen {
		return nil, io.ErrShortBuffer
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil, io.ErrShortBuffer
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = SocksAddressIPv4Length
	case AtypIPv6:
		addrLen = SocksAddressIPv6Length
	default:
		return nil, fmt.Errorf("unknown atyp %v", b[0])
	}

	if len(b) < addrLen {
		return nil, io.ErrShortBuffer
	}

	return b[:addrLen], nil
}

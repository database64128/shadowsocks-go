package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/database64128/shadowsocks-go/cache"
	"github.com/database64128/shadowsocks-go/conn"
)

// SOCKS5 address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

const (
	// IPv4AddrLen is the size of an IPv4 SOCKS5 address in bytes.
	IPv4AddrLen = 1 + 4 + 2

	// IPv6AddrLen is the size of an IPv6 SOCKS5 address in bytes.
	IPv6AddrLen = 1 + 16 + 2

	// MaxAddrLen is the maximum size of a SOCKS5 address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2
)

var (
	// IPv4UnspecifiedAddr represents 0.0.0.0:0.
	IPv4UnspecifiedAddr = [IPv4AddrLen]byte{AtypIPv4}

	// IPv6UnspecifiedAddr represents [::]:0.
	IPv6UnspecifiedAddr = [IPv6AddrLen]byte{AtypIPv6}
)

// InvalidATYPError represents the error that the address type (ATYP) byte in a SOCKS5 address is invalid.
type InvalidATYPError byte

func (e InvalidATYPError) Error() string {
	return fmt.Sprintf("invalid ATYP: %#x", byte(e))
}

// NotEnoughBytesError represents the error that there are not enough bytes
// in the input byte slice for a SOCKS5 address.
type NotEnoughBytesError struct {
	Len  uint16
	ATYP byte
}

func (e NotEnoughBytesError) Error() string {
	if e.ATYP != 0 {
		return fmt.Sprintf("not enough bytes for ATYP %#x: %d", e.ATYP, e.Len)
	}
	return fmt.Sprintf("not enough bytes: %d", e.Len)
}

// AppendAddrFromAddrPort appends addrPort to b in the
// SOCKS5 address format and returns the updated slice.
//
//   - The zero value address is treated as [::]:0.
//   - IPv4-mapped IPv6 addresses are unmapped to IPv4.
//   - Any IPv6 zone identifier is silently ignored.
func AppendAddrFromAddrPort(b []byte, addrPort netip.AddrPort) []byte {
	if ip := addrPort.Addr(); ip.Is4() || ip.Is4In6() {
		ip4 := ip.As4()
		b = append(b, AtypIPv4)
		b = append(b, ip4[:]...)
	} else {
		ip6 := ip.As16()
		b = append(b, AtypIPv6)
		b = append(b, ip6[:]...)
	}
	return binary.BigEndian.AppendUint16(b, addrPort.Port())
}

// PutAddrFromAddrPort stores addrPort into b in the SOCKS5 address format
// and returns the number of bytes written.
//
//   - The zero value address is treated as [::]:0.
//   - IPv4-mapped IPv6 addresses are unmapped to IPv4.
//   - Any IPv6 zone identifier is silently ignored.
//
// b must have sufficient space for the address, or the function will panic.
// Call [LengthOfAddrFromAddrPort] to get the required space for the address.
func PutAddrFromAddrPort(b []byte, addrPort netip.AddrPort) (n int) {
	if ip := addrPort.Addr(); ip.Is4() || ip.Is4In6() {
		if len(b) < 1+4+2 {
			panic("socks5.WriteAddrFromAddrPort: buffer too small for IPv4 address")
		}
		b[0] = AtypIPv4
		*(*[4]byte)(b[1:]) = ip.As4()
		binary.BigEndian.PutUint16(b[1+4:], addrPort.Port())
		return 1 + 4 + 2
	} else {
		if len(b) < 1+16+2 {
			panic("socks5.WriteAddrFromAddrPort: buffer too small for IPv6 address")
		}
		b[0] = AtypIPv6
		*(*[16]byte)(b[1:]) = ip.As16()
		binary.BigEndian.PutUint16(b[1+16:], addrPort.Port())
		return 1 + 16 + 2
	}
}

// LengthOfAddrFromAddrPort returns the length of the SOCKS5 address representing addrPort.
func LengthOfAddrFromAddrPort(addrPort netip.AddrPort) int {
	if ip := addrPort.Addr(); ip.Is4() || ip.Is4In6() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

// AppendAddrFromConnAddr appends addr to b in the SOCKS5 address format and returns the updated slice.
//
//   - The zero value address is treated as 0.0.0.0:0.
//   - IPv4-mapped IPv6 addresses are unmapped to IPv4.
//   - Any IPv6 zone identifier is silently ignored.
func AppendAddrFromConnAddr(b []byte, addr conn.Addr) []byte {
	if !addr.IsValid() {
		return AppendAddrFromAddrPort(b, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	}
	if addr.IsIP() {
		return AppendAddrFromAddrPort(b, addr.IPPort())
	}
	if !addr.IsDomain() {
		panic("socks5.AppendAddrFromConnAddr: " + conn.UnsupportedAddressKindErrorFromAddr(addr).Error())
	}

	domain := addr.Domain().String()
	if len(domain) > 255 {
		panic(fmt.Sprintf("socks5.AppendAddrFromConnAddr: domain name too long: %d > 255", len(domain)))
	}
	b = append(b, AtypDomainName, byte(len(domain)))
	b = append(b, domain...)
	return binary.BigEndian.AppendUint16(b, addr.Port())
}

// PutAddrFromConnAddr stores addr into b in the SOCKS5 address format
// and returns the number of bytes written.
//
// - The zero value address is treated as 0.0.0.0:0.
// - IPv4-mapped IPv6 addresses are unmapped to IPv4.
// - Any IPv6 zone identifier is silently ignored.
//
// b must have sufficient space for the address, or the function will panic.
// Call [LengthOfAddrFromConnAddr] to get the required space for the address.
func PutAddrFromConnAddr(b []byte, addr conn.Addr) int {
	if !addr.IsValid() {
		return PutAddrFromAddrPort(b, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	}
	if addr.IsIP() {
		return PutAddrFromAddrPort(b, addr.IPPort())
	}
	if !addr.IsDomain() {
		panic("socks5.PutAddrFromConnAddr: " + conn.UnsupportedAddressKindErrorFromAddr(addr).Error())
	}

	domain := addr.Domain().String()
	if len(domain) > 255 {
		panic(fmt.Sprintf("socks5.PutAddrFromConnAddr: domain name too long: %d > 255", len(domain)))
	}

	n := 1 + 1 + len(domain) + 2
	if len(b) < n {
		panic(fmt.Sprintf("socks5.PutAddrFromConnAddr: buffer too small: %d < %d", len(b), n))
	}

	b[0] = AtypDomainName
	b[1] = byte(len(domain))
	copy(b[2:], domain)

	port := addr.Port()
	binary.BigEndian.PutUint16(b[1+1+len(domain):], port)

	return n
}

// LengthOfAddrFromConnAddr returns the length of the SOCKS5 address representing addr.
func LengthOfAddrFromConnAddr(addr conn.Addr) int {
	if !addr.IsValid() {
		return 1 + 4 + 2
	}
	if addr.IsIP() {
		return LengthOfAddrFromAddrPort(addr.IPPort())
	}
	if !addr.IsDomain() {
		panic("socks5.LengthOfAddrFromConnAddr: " + conn.UnsupportedAddressKindErrorFromAddr(addr).Error())
	}
	return 1 + 1 + addr.DomainLen() + 2
}

// AppendAddrFromReader reads a SOCKS5 address from r and appends it to b.
// It returns the updated slice or an error.
func AppendAddrFromReader(b []byte, r io.Reader) ([]byte, error) {
	bLen := len(b)
	b = slices.Grow(b, 2)[:bLen+2]
	readBuf := b[bLen:]

	// Read ATYP and an extra byte.
	if _, err := io.ReadFull(r, readBuf); err != nil {
		return nil, toUnexpectedEOF(err)
	}

	var readBufSize int
	switch readBuf[0] {
	case AtypDomainName:
		readBufSize = int(readBuf[1]) + 2
	case AtypIPv4:
		readBufSize = -2 + 1 + 4 + 2
	case AtypIPv6:
		readBufSize = -2 + 1 + 16 + 2
	default:
		return nil, InvalidATYPError(readBuf[0])
	}

	bLen = len(b)
	b = slices.Grow(b, readBufSize)[:bLen+readBufSize]
	readBuf = b[bLen:]
	if _, err := io.ReadFull(r, readBuf); err != nil {
		return nil, toUnexpectedEOF(err)
	}
	return b, nil
}

// ConnAddrFromReader reads and parses a SOCKS5 address from r,
// using b as the scratch space. It returns the address as a
// [conn.Addr] on success.
func ConnAddrFromReader(r io.Reader, b []byte) (conn.Addr, error) {
	b = slices.Grow(b[:0], 1+16+2)[:1+16+2]

	// Read ATYP and an extra byte.
	if _, err := io.ReadFull(r, b[:2]); err != nil {
		return conn.Addr{}, toUnexpectedEOF(err)
	}

	switch b[0] {
	case AtypDomainName:
		domainLen := int(b[1])
		b = slices.Grow(b[:0], domainLen+2)[:domainLen+2]
		if _, err := io.ReadFull(r, b); err != nil {
			return conn.Addr{}, toUnexpectedEOF(err)
		}
		domain := b[:domainLen]
		port := binary.BigEndian.Uint16(b[domainLen:])
		return conn.AddrFromDomainBytesAndPort(domain, port)

	case AtypIPv4:
		if _, err := io.ReadFull(r, b[2:1+4+2]); err != nil {
			return conn.Addr{}, toUnexpectedEOF(err)
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return conn.AddrFromIPAndPort(ip, port), nil

	case AtypIPv6:
		if _, err := io.ReadFull(r, b[2:1+16+2]); err != nil {
			return conn.Addr{}, toUnexpectedEOF(err)
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return conn.AddrFromIPAndPort(ip, port), nil

	default:
		return conn.Addr{}, InvalidATYPError(b[0])
	}
}

var ErrAddrDomain = errors.New("address is a domain name")

// AddrPortFromBytes parses the SOCKS5 address at the beginning of b. On success,
// it returns the address as a [netip.AddrPort] and the number of bytes consumed.
func AddrPortFromBytes(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 1+4+2 {
		return netip.AddrPort{}, 0, NotEnoughBytesError{Len: uint16(len(b))}
	}

	switch b[0] {
	case AtypIPv4:
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return netip.AddrPortFrom(ip, port), 1 + 4 + 2, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return netip.AddrPort{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return netip.AddrPortFrom(ip, port), 1 + 16 + 2, nil

	case AtypDomainName:
		return netip.AddrPort{}, 0, ErrAddrDomain

	default:
		return netip.AddrPort{}, 0, InvalidATYPError(b[0])
	}
}

// ConnAddrFromBytes parses the SOCKS5 address at the beginning of b. On success,
// it returns the address as a [conn.Addr] and the number of bytes consumed.
func ConnAddrFromBytes(b []byte) (conn.Addr, int, error) {
	if len(b) < 2 {
		return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b))}
	}

	switch b[0] {
	case AtypDomainName:
		domainLen := int(b[1])
		domainEnd := 1 + 1 + domainLen
		portEnd := domainEnd + 2
		if len(b) < portEnd {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		domain := b[2:domainEnd]
		port := binary.BigEndian.Uint16(b[domainEnd:])
		addr, err := conn.AddrFromDomainBytesAndPort(domain, port)
		return addr, portEnd, err

	case AtypIPv4:
		if len(b) < 1+4+2 {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return conn.AddrFromIPAndPort(ip, port), 1 + 4 + 2, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1:]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return conn.AddrFromIPAndPort(ip, port), 1 + 16 + 2, nil

	default:
		return conn.Addr{}, 0, InvalidATYPError(b[0])
	}
}

// DomainCache caches domain strings to reduce allocations when parsing domain name SOCKS5 addresses.
//
// The zero value is ready for use.
type DomainCache struct {
	handleByDomain *cache.BoundedCache[string, conn.Domain]
}

// ConnAddrFromBytes is like [ConnAddrFromBytes] but uses the domain cache to minimize string allocations.
func (c *DomainCache) ConnAddrFromBytes(b []byte) (conn.Addr, int, error) {
	if len(b) < 2 {
		return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b))}
	}

	switch b[0] {
	case AtypDomainName:
		domainLen := int(b[1])
		domainEnd := 1 + 1 + domainLen
		portEnd := domainEnd + 2
		if len(b) < portEnd {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}

		if c.handleByDomain == nil {
			// Initialize the cache with a reasonable size.
			const domainCacheSize = 32
			c.handleByDomain = cache.NewBoundedCache[string, conn.Domain](domainCacheSize)
		}

		domainBytes := b[2:domainEnd]
		domain, ok := c.handleByDomain.Get(string(domainBytes))
		if !ok {
			var err error
			domain, err = conn.DomainFromByteString(domainBytes)
			if err != nil {
				return conn.Addr{}, 0, err
			}

			var key string
			if s := domain.String(); s == string(domainBytes) {
				key = s
			} else {
				key = string(domainBytes)
			}
			c.handleByDomain.InsertUnchecked(key, domain)
		}
		port := binary.BigEndian.Uint16(b[domainEnd:])
		return conn.AddrFromDomainPort(domain, port), portEnd, nil

	case AtypIPv4:
		if len(b) < 1+4+2 {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		ip := netip.AddrFrom4(*(*[4]byte)(b[1 : 1+4]))
		port := binary.BigEndian.Uint16(b[1+4:])
		return conn.AddrFromIPAndPort(ip, port), 1 + 4 + 2, nil

	case AtypIPv6:
		if len(b) < 1+16+2 {
			return conn.Addr{}, 0, NotEnoughBytesError{Len: uint16(len(b)), ATYP: b[0]}
		}
		ip := netip.AddrFrom16(*(*[16]byte)(b[1 : 1+16]))
		port := binary.BigEndian.Uint16(b[1+16:])
		return conn.AddrFromIPAndPort(ip, port), 1 + 16 + 2, nil

	default:
		return conn.Addr{}, 0, InvalidATYPError(b[0])
	}
}

// toUnexpectedEOF converts [io.EOF] to [io.ErrUnexpectedEOF].
func toUnexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

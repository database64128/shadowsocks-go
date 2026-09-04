package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"
)

type addressFamily byte

const (
	addressFamilyNone addressFamily = iota
	addressFamilyNetip
	addressFamilyDomain
)

// UnsupportedAddressKindError is the error type for unsupported address kinds.
type UnsupportedAddressKindError struct {
	af addressFamily
}

// UnsupportedAddressKindErrorFromAddr returns an [UnsupportedAddressKindError] for the given address.
func UnsupportedAddressKindErrorFromAddr(addr Addr) UnsupportedAddressKindError {
	return UnsupportedAddressKindError{af: addr.af}
}

func (e UnsupportedAddressKindError) Error() string {
	switch e.af {
	case addressFamilyNone:
		return "unsupported address kind: none"
	case addressFamilyNetip:
		return "unsupported address kind: netip"
	case addressFamilyDomain:
		return "unsupported address kind: domain"
	default:
		return fmt.Sprintf("unsupported address kind: invalid(%d)", e.af)
	}
}

func (e UnsupportedAddressKindError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

type netipAddrHeader struct {
	hi uint64
	lo uint64
	z  *byte
}

// Addr is the base address type used throughout the package.
//
// An Addr is a port number combined with either an IP address or a domain name.
//
// For space efficiency, the IP address and the domain string share the same space.
// The [netip.Addr] is stored in its original layout.
// The domain string's data pointer is stored in the ip.z field.
// Its length is stored at the beginning of the structure.
// This is essentially an unsafe "enum".
type Addr struct {
	_    [0]func()
	addr netipAddrHeader
	port uint16
	af   addressFamily
}

func (a Addr) ip() netip.Addr {
	return *(*netip.Addr)(unsafe.Pointer(&a))
}

func (a Addr) ipPort() netip.AddrPort {
	return *(*netip.AddrPort)(unsafe.Pointer(&a))
}

func (a Addr) domain() string {
	return unsafe.String(a.addr.z, a.addr.hi)
}

// Equals returns whether two addresses are the same.
func (a Addr) Equals(b Addr) bool {
	if a.af != b.af || a.port != b.port {
		return false
	}

	switch a.af {
	case addressFamilyNetip:
		return a.addr == b.addr
	case addressFamilyDomain:
		return a.domain() == b.domain()
	default:
		return true
	}
}

// IsValid returns whether the address is an initialized address (not a zero value).
func (a Addr) IsValid() bool {
	return a.af != addressFamilyNone
}

// IsIP returns whether the address is an IP address.
func (a Addr) IsIP() bool {
	return a.af == addressFamilyNetip
}

// IsDomain returns whether the address is a domain name.
func (a Addr) IsDomain() bool {
	return a.af == addressFamilyDomain
}

// IP returns the IP address.
//
// If the address is a domain name or zero value, this method panics.
func (a Addr) IP() netip.Addr {
	if a.af != addressFamilyNetip {
		panic("IP() called on non-IP address")
	}
	return a.ip()
}

// Domain returns the domain name.
//
// If the address is an IP address or zero value, this method panics.
func (a Addr) Domain() string {
	if a.af != addressFamilyDomain {
		panic("Domain() called on non-domain address")
	}
	return a.domain()
}

// Port returns the port number.
func (a Addr) Port() uint16 {
	return a.port
}

// IPPort returns a netip.AddrPort.
//
// If the address is a domain name or zero value, this method panics.
func (a Addr) IPPort() netip.AddrPort {
	if a.af != addressFamilyNetip {
		panic("IPPort() called on non-IP address")
	}
	return a.ipPort()
}

// Resolver is an interface for resolving domain names into IP addresses.
type Resolver interface {
	// LookupNetIP looks up host using the local resolver.
	// It returns a slice of that host's IP addresses of the type specified by
	// network.
	// The network must be one of "ip", "ip4" or "ip6".
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// ResolveIP resolves a domain name string into an IP address.
//
// The network must be one of "ip", "ip4" or "ip6".
// String representations of IP addresses are not supported.
//
// If resolver is nil, [net.DefaultResolver] is used.
//
// This function always returns the first IP address returned by the resolver,
// because the resolver takes care of sorting the IP addresses by address family
// availability and preference.
func ResolveIP(ctx context.Context, network, host string, resolver Resolver) (netip.Addr, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ips[0], nil
}

// ResolveIP returns the IP address itself or the resolved IP address of the domain name.
//
// The network is only used for domain name resolution and must be one of "ip", "ip4" or "ip6".
//
// If resolver is nil, [net.DefaultResolver] is used.
//
// If the address is the zero value, this method panics.
func (a Addr) ResolveIP(ctx context.Context, network string, resolver Resolver) (netip.Addr, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ip(), nil
	case addressFamilyDomain:
		return ResolveIP(ctx, network, a.domain(), resolver)
	default:
		panic("ResolveIP() called on zero value")
	}
}

// ResolveIPPort returns the IP address itself or the resolved IP address of the domain name
// and the port number as a [netip.AddrPort].
//
// The network is only used for domain name resolution and must be one of "ip", "ip4" or "ip6".
//
// If resolver is nil, [net.DefaultResolver] is used.
//
// If the address is the zero value, this method panics.
func (a Addr) ResolveIPPort(ctx context.Context, network string, resolver Resolver) (netip.AddrPort, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort(), nil
	case addressFamilyDomain:
		ip, err := ResolveIP(ctx, network, a.domain(), resolver)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, a.port), nil
	default:
		panic("ResolveIPPort() called on zero value")
	}
}

// Host returns the string representation of the IP address or the domain name.
//
// If the address is the zero value, this method panics.
func (a Addr) Host() string {
	switch a.af {
	case addressFamilyNetip:
		return a.ip().String()
	case addressFamilyDomain:
		return a.domain()
	default:
		panic("Host() called on zero value")
	}
}

// String returns the string representation of the address.
//
// If the address is the zero value, an empty string is returned.
func (a Addr) String() string {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().String()
	case addressFamilyDomain:
		b := make([]byte, 0, 255+1+5) // domain + ':' + port
		b = a.appendTextDomain(b)
		return string(b)
	default:
		return ""
	}
}

// MaxTextLen returns the maximum number of bytes its textual representation can take up.
func (a Addr) MaxTextLen() int {
	switch a.af {
	case addressFamilyNetip:
		ip := a.ip()
		switch {
		case ip.Is4():
			return len("255.255.255.255:65535")
		case ip.Is4In6():
			return len("[::ffff:255.255.255.255%enp5s0]:65535")
		case ip.Is6():
			return len("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0]:65535")
		default:
			return 0
		}
	case addressFamilyDomain:
		return int(a.addr.hi) + 1 + 5 // domain + ':' + port
	default:
		return 0
	}
}

// AppendTo appends the textual representation of the address to b and returns the updated slice.
//
// If the address is the zero value, b is returned unchanged.
func (a Addr) AppendTo(b []byte) []byte {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().AppendTo(b)
	case addressFamilyDomain:
		return a.appendTextDomain(b)
	default:
		return b
	}
}

func (a Addr) appendTextDomain(b []byte) []byte {
	b = append(b, a.domain()...)
	b = append(b, ':')
	return strconv.AppendUint(b, uint64(a.port), 10)
}

// AppendText appends the textual representation of the address to b and returns the updated slice.
//
// If the address is the zero value, b is returned unchanged.
//
// AppendText implements [encoding.TextAppender].
func (a Addr) AppendText(b []byte) ([]byte, error) {
	return a.AppendTo(b), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (a Addr) MarshalText() ([]byte, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().MarshalText()
	case addressFamilyDomain:
		b := make([]byte, 0, a.addr.hi+1+5) // domain + ':' + port
		return a.appendTextDomain(b), nil
	default:
		return nil, nil
	}
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (a *Addr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*a = Addr{}
		return nil
	}
	addr, err := ParseAddr(string(text))
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// AddrFromIPPort returns an Addr from the provided netip.AddrPort.
func AddrFromIPPort(addrPort netip.AddrPort) (addr Addr) {
	*(*netip.AddrPort)(unsafe.Pointer(&addr)) = addrPort
	addr.af = addressFamilyNetip
	return
}

// AddrFromIPAndPort returns an Addr from the provided IP address and port number.
func AddrFromIPAndPort(ip netip.Addr, port uint16) Addr {
	return Addr{
		addr: *(*netipAddrHeader)(unsafe.Pointer(&ip)),
		port: port,
		af:   addressFamilyNetip,
	}
}

// AddrFromDomainPort returns an Addr from the provided domain name and port number.
func AddrFromDomainPort(domain string, port uint16) (Addr, error) {
	if len(domain) == 0 || len(domain) > 255 {
		return Addr{}, fmt.Errorf("length of domain %s out of range [1, 255]", domain)
	}
	return Addr{
		addr: netipAddrHeader{
			hi: uint64(len(domain)),
			z:  unsafe.StringData(domain),
		},
		port: port,
		af:   addressFamilyDomain,
	}, nil
}

// MustAddrFromDomainPort calls [AddrFromDomainPort] and panics on error.
func MustAddrFromDomainPort(domain string, port uint16) Addr {
	addr, err := AddrFromDomainPort(domain, port)
	if err != nil {
		panic(err)
	}
	return addr
}

// AddrFromHostPort returns an Addr from the provided host string and port number.
// The host string may be a string representation of an IP address or a domain name.
func AddrFromHostPort(host string, port uint16) (Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return AddrFromIPAndPort(ip, port), nil
	}
	return AddrFromDomainPort(host, port)
}

// ParseAddr parses the provided string representation of an address
// and returns the parsed address or an error.
func ParseAddr(s string) (Addr, error) {
	host, portString, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}

	portNumber, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("failed to parse port string: %w", err)
	}
	port := uint16(portNumber)

	return AddrFromHostPort(host, port)
}

type addrPortHeader struct {
	ip   [16]byte
	z    unsafe.Pointer
	port uint16
}

// AddrPortMappedEqual returns whether the two addresses point to the same endpoint.
// An IPv4 address and an IPv4-mapped IPv6 address pointing to the same endpoint are considered equal.
// For example, 1.1.1.1:53 and [::ffff:1.1.1.1]:53 are considered equal.
func AddrPortMappedEqual(l, r netip.AddrPort) bool {
	lp := (*addrPortHeader)(unsafe.Pointer(&l))
	rp := (*addrPortHeader)(unsafe.Pointer(&r))
	return lp.ip == rp.ip && lp.port == rp.port
}

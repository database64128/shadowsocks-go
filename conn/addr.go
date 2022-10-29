package conn

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"
)

// Addr is the base address type used throughout the package.
//
// An Addr is a port number combined with either an IP address or a domain name.
type Addr struct {
	ip     netip.Addr
	port   uint16
	domain string
}

// IsIP returns whether the address is an IP address.
// If false, the address is a domain name.
func (a Addr) IsIP() bool {
	return a.ip.IsValid()
}

// IP returns the IP address.
// If the address is a domain name, the returned netip.Addr is a zero value.
func (a Addr) IP() netip.Addr {
	return a.ip
}

// Domain returns the domain name.
// If the address is an IP address, the returned domain name is an empty string.
func (a Addr) Domain() string {
	return a.domain
}

// Port returns the port number.
func (a Addr) Port() uint16 {
	return a.port
}

// IPPort returns a netip.AddrPort.
// If the address is a domain name, the returned netip.AddrPort contains a zero-value netip.Addr
// and the port number.
func (a Addr) IPPort() netip.AddrPort {
	return *(*netip.AddrPort)(unsafe.Pointer(&a))
}

// ResolveIP returns the IP address itself or the resolved IP address of the domain name.
func (a Addr) ResolveIP() (netip.Addr, error) {
	if a.ip.IsValid() {
		return a.ip, nil
	}
	return ResolveAddr(a.domain)
}

// ResolveIPPort returns the IP address itself or the resolved IP address of the domain name
// and the port number as a netip.AddrPort.
func (a Addr) ResolveIPPort() (netip.AddrPort, error) {
	if a.ip.IsValid() {
		return a.IPPort(), nil
	}

	ip, err := ResolveAddr(a.domain)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, a.port), nil
}

// Host returns the string representation of the IP address or the domain name.
func (a Addr) Host() string {
	if a.ip.IsValid() {
		return a.ip.String()
	}
	return a.domain
}

// String returns the string representation of the address.
func (a Addr) String() string {
	if a.ip.IsValid() {
		return (*netip.AddrPort)(unsafe.Pointer(&a)).String()
	}
	return fmt.Sprintf("%s:%d", a.domain, a.port)
}

// AppendTo appends the string representation of the address to the provided buffer.
func (a Addr) AppendTo(b []byte) []byte {
	if a.ip.IsValid() {
		return (*netip.AddrPort)(unsafe.Pointer(&a)).AppendTo(b)
	}
	return fmt.Appendf(b, "%s:%d", a.domain, a.port)
}

// MarshalText implements the encoding.TextMarshaler MarshalText method.
func (a Addr) MarshalText() ([]byte, error) {
	if a.ip.IsValid() {
		return (*netip.AddrPort)(unsafe.Pointer(&a)).MarshalText()
	}
	return fmt.Appendf(nil, "%s:%d", a.domain, a.port), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler UnmarshalText method.
func (a *Addr) UnmarshalText(text []byte) error {
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
	return
}

// AddrFromDomainPort returns an Addr from the provided domain name and port number.
func AddrFromDomainPort(domain string, port uint16) (Addr, error) {
	if len(domain) > 255 {
		return Addr{}, fmt.Errorf("length of domain %s exceeds 255", domain)
	}
	return Addr{domain: domain, port: port}, nil
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
	if host == "" {
		host = "::"
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return Addr{ip: ip, port: port}, nil
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

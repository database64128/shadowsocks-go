package conn

import (
	"context"
	"net"
	"net/netip"
)

// ResolveAddr resolves a domain name string into an IP address.
//
// This function always returns the first IP address returned by the resolver,
// because the resolver takes care of sorting the IP addresses by address family
// availability and preference.
//
// String representations of IP addresses are not supported.
func ResolveAddr(host string) (netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ips[0], nil
}

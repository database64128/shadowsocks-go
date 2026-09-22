package netio

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/prefixset"
)

// AddressFamilyPreference specifies the preference for IPv4 or IPv6 addresses
// when connecting to an endpoint.
type AddressFamilyPreference uint8

const (
	// AddressFamilyPreferenceDefault keeps the Go net package and/or the host system's default.
	AddressFamilyPreferenceDefault AddressFamilyPreference = iota

	// AddressFamilyPreferencePreferIPv6 prefers IPv6 addresses over IPv4 addresses.
	AddressFamilyPreferencePreferIPv6

	// AddressFamilyPreferencePreferIPv4 prefers IPv4 addresses over IPv6 addresses.
	AddressFamilyPreferencePreferIPv4

	// AddressFamilyPreferenceIPv6Only uses IPv6 addresses only.
	AddressFamilyPreferenceIPv6Only

	// AddressFamilyPreferenceIPv4Only uses IPv4 addresses only.
	AddressFamilyPreferenceIPv4Only

	addressFamilyPreferenceMax = AddressFamilyPreferenceIPv4Only
)

// IsValid returns true if p is a valid value.
func (p AddressFamilyPreference) IsValid() bool {
	return p <= addressFamilyPreferenceMax
}

const (
	addressFamilyPreferenceDefaultString    = "default"
	addressFamilyPreferencePreferIPv6String = "prefer-ipv6"
	addressFamilyPreferencePreferIPv4String = "prefer-ipv4"
	addressFamilyPreferenceIPv6OnlyString   = "ipv6-only"
	addressFamilyPreferenceIPv4OnlyString   = "ipv4-only"
)

// String returns its string representation.
func (p AddressFamilyPreference) String() string {
	switch p {
	case AddressFamilyPreferenceDefault:
		return addressFamilyPreferenceDefaultString
	case AddressFamilyPreferencePreferIPv6:
		return addressFamilyPreferencePreferIPv6String
	case AddressFamilyPreferencePreferIPv4:
		return addressFamilyPreferencePreferIPv4String
	case AddressFamilyPreferenceIPv6Only:
		return addressFamilyPreferenceIPv6OnlyString
	case AddressFamilyPreferenceIPv4Only:
		return addressFamilyPreferenceIPv4OnlyString
	default:
		return fmt.Sprintf("invalid(%d)", p)
	}
}

// AppendText appends its textual representation to b and returns the updated slice.
//
// AppendText implements [encoding.TextAppender].
func (p AddressFamilyPreference) AppendText(b []byte) ([]byte, error) {
	switch p {
	case AddressFamilyPreferenceDefault:
		return append(b, addressFamilyPreferenceDefaultString...), nil
	case AddressFamilyPreferencePreferIPv6:
		return append(b, addressFamilyPreferencePreferIPv6String...), nil
	case AddressFamilyPreferencePreferIPv4:
		return append(b, addressFamilyPreferencePreferIPv4String...), nil
	case AddressFamilyPreferenceIPv6Only:
		return append(b, addressFamilyPreferenceIPv6OnlyString...), nil
	case AddressFamilyPreferenceIPv4Only:
		return append(b, addressFamilyPreferenceIPv4OnlyString...), nil
	default:
		return nil, fmt.Errorf("invalid address family preference: %d", p)
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (p AddressFamilyPreference) MarshalText() ([]byte, error) {
	return p.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (p *AddressFamilyPreference) UnmarshalText(text []byte) error {
	switch string(text) {
	case addressFamilyPreferenceDefaultString:
		*p = AddressFamilyPreferenceDefault
	case addressFamilyPreferencePreferIPv6String:
		*p = AddressFamilyPreferencePreferIPv6
	case addressFamilyPreferencePreferIPv4String:
		*p = AddressFamilyPreferencePreferIPv4
	case addressFamilyPreferenceIPv6OnlyString:
		*p = AddressFamilyPreferenceIPv6Only
	case addressFamilyPreferenceIPv4OnlyString:
		*p = AddressFamilyPreferenceIPv4Only
	default:
		return fmt.Errorf("invalid address family preference: %q", text)
	}
	return nil
}

// FilterIP returns an error if ip is disallowed by the address family preference.
func (p AddressFamilyPreference) FilterIP(ip netip.Addr) error {
	if p == AddressFamilyPreferenceIPv6Only && (!ip.Is6() || ip.Is4In6()) ||
		p == AddressFamilyPreferenceIPv4Only && !ip.Is4() && !ip.Is4In6() {
		return AddressFamilyPreferenceMismatchError(p)
	}
	return nil
}

// AddressFamilyPreferenceMismatchError represents an incompatibility
// between an address and the specified address family preference.
type AddressFamilyPreferenceMismatchError AddressFamilyPreference

func (e AddressFamilyPreferenceMismatchError) Error() string {
	return `address not suitable for address family preference "` + AddressFamilyPreference(e).String() + `"`
}

func (e AddressFamilyPreferenceMismatchError) Unwrap() error {
	return conn.DialResultCodeENETUNREACH
}

// ResolveIPPort returns the IP address itself or the first resolved IP address of the domain name
// along with the port number, following the address family preference.
//
// If resolver is nil, [net.DefaultResolver] is used.
func ResolveIPPort(
	ctx context.Context,
	addr conn.Addr,
	pref AddressFamilyPreference,
	resolver conn.Resolver,
) (netip.AddrPort, error) {
	ip, err := ResolveIP(ctx, addr, pref, resolver)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, addr.Port()), nil
}

// ResolveIP returns the IP address itself or the first resolved IP address of the domain name,
// following the address family preference.
//
// If resolver is nil, [net.DefaultResolver] is used.
func ResolveIP(
	ctx context.Context,
	addr conn.Addr,
	pref AddressFamilyPreference,
	resolver conn.Resolver,
) (netip.Addr, error) {
	switch {
	case addr.IsIP():
		ip := addr.IP()
		if err := pref.FilterIP(ip); err != nil {
			return netip.Addr{}, err
		}
		return ip, nil

	case addr.IsDomain():
		domain := addr.Domain()
		switch pref {
		case AddressFamilyPreferenceDefault:
			return conn.ResolveIP(ctx, "ip", domain, resolver)
		case AddressFamilyPreferencePreferIPv6:
			return resolveIPPreferredSecondary(ctx, "ip6", "ip4", domain, resolver)
		case AddressFamilyPreferencePreferIPv4:
			return resolveIPPreferredSecondary(ctx, "ip4", "ip6", domain, resolver)
		case AddressFamilyPreferenceIPv6Only:
			return conn.ResolveIP(ctx, "ip6", domain, resolver)
		case AddressFamilyPreferenceIPv4Only:
			return conn.ResolveIP(ctx, "ip4", domain, resolver)
		default:
			return netip.Addr{}, fmt.Errorf("invalid address family preference: %d", pref)
		}

	default:
		return netip.Addr{}, conn.UnsupportedAddressKindErrorFromAddr(addr)
	}
}

// resolveIPPreferredSecondary tries to resolve the domain name to IP addresses
// of the preferred and secondary networks in parallel, returning as soon as the
// preferred resolution succeeds.
func resolveIPPreferredSecondary(
	ctx context.Context,
	preferredNetwork string,
	secondaryNetwork string,
	domain string,
	resolver conn.Resolver,
) (ip netip.Addr, err error) {
	type lookupResult struct {
		IP        netip.Addr
		Err       error
		Preferred bool
	}

	attemptCtx, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()
	attemptCtxDone := attemptCtx.Done()

	lookupResultCh := make(chan lookupResult)
	lookup := func(network string, preferred bool) {
		ip, err := conn.ResolveIP(attemptCtx, network, domain, resolver)
		select {
		case lookupResultCh <- lookupResult{IP: ip, Err: err, Preferred: preferred}:
		case <-attemptCtxDone:
		}
	}
	go lookup(preferredNetwork, true)
	go lookup(secondaryNetwork, false)

	select {
	case result := <-lookupResultCh:
		ip, err = result.IP, result.Err
		if result.Preferred && err == nil {
			return ip, nil
		}
	case <-attemptCtxDone:
		return netip.Addr{}, attemptCtx.Err()
	}

	select {
	case result := <-lookupResultCh:
		switch {
		case result.Err == nil:
			return result.IP, nil
		case err == nil:
			return ip, nil
		default:
			return netip.Addr{}, errors.Join(err, result.Err)
		}
	case <-attemptCtxDone:
		return netip.Addr{}, attemptCtx.Err()
	}
}

// IPAllowDenyList consists of an allowlist and a denylist of IP address prefixes.
//
// Both lists can be nil, indicating no restrictions.
type IPAllowDenyList struct {
	// Allowlist contains the allowed IP address prefixes.
	//
	// If nil, there are no allowlist restrictions.
	Allowlist *prefixset.PrefixSet

	// Denylist contains the disallowed IP address prefixes.
	//
	// If nil, there are no denylist restrictions.
	Denylist *prefixset.PrefixSet
}

// Check returns an error if ip is not allowed by the allowlist or denylist rules.
func (acl IPAllowDenyList) Check(ip netip.Addr) error {
	if acl.Allowlist != nil && !acl.Allowlist.Contains(ip) {
		return AddrNotInAllowlistError{}
	}
	if acl.Denylist != nil && acl.Denylist.Contains(ip) {
		return AddrInDenylistError{}
	}
	return nil
}

// AddrNotInAllowlistError is returned when the destination address is not in the allowlist.
type AddrNotInAllowlistError struct{}

func (AddrNotInAllowlistError) Error() string {
	return "address not in allowlist"
}

func (AddrNotInAllowlistError) Unwrap() error {
	return conn.DialResultCodeEACCES
}

// AddrInDenylistError is returned when the destination address is in the denylist.
type AddrInDenylistError struct{}

func (AddrInDenylistError) Error() string {
	return "address in denylist"
}

func (AddrInDenylistError) Unwrap() error {
	return conn.DialResultCodeEACCES
}

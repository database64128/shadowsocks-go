package netio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

// TCPClientConfig is the configuration for a TCP client.
type TCPClientConfig struct {
	// Name is the name of the client.
	Name string

	// AddressFamilyPreference specifies the preference for IPv4 or IPv6 addresses
	// when connecting to an endpoint.
	AddressFamilyPreference AddressFamilyPreference

	// ResolutionDelay specifies the amount of time to wait for the preferred address family's DNS records
	// after receiving the non-preferred ones, before starting connection attempts with received addresses.
	//
	// If zero, the default is 50ms.
	ResolutionDelay time.Duration

	// ConnectionAttemptDelay specifies the interval between connection attempts.
	//
	// It must be in the range [50ms, 2s]. If zero, the default is 250ms.
	ConnectionAttemptDelay time.Duration

	// LocalAddr4 specifies an optional local IPv4 address and port to bind to
	// when connecting to an IPv4 destination address.
	LocalAddr4 netip.AddrPort

	// LocalAddr6 specifies an optional local IPv6 address and port to bind to
	// when connecting to an IPv6 destination address.
	LocalAddr6 netip.AddrPort

	// Dialer specifies the underlying TCP dialer to use for establishing connections.
	Dialer conn.TCPDialer

	// Resolver specifies the DNS resolver to use for resolving domain names.
	//
	// If nil, [net.DefaultResolver] is used.
	Resolver conn.Resolver
}

// Happy Eyeballs v3 defaults, as defined in the draft RFC:
// https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-04.html
//
// Note that we don't use the exact values from the RFC, for practical reasons.
const (
	defaultResolutionDelay        = 50 * time.Millisecond
	defaultConnectionAttemptDelay = 250 * time.Millisecond
	minimumConnectionAttemptDelay = 50 * time.Millisecond
	maximumConnectionAttemptDelay = 2 * time.Second
)

// NewTCPClient returns a new TCP client.
func (c *TCPClientConfig) NewTCPClient() (*TCPClient, error) {
	if !c.AddressFamilyPreference.IsValid() {
		return nil, fmt.Errorf("invalid address family preference: %d", c.AddressFamilyPreference)
	}

	resolutionDelay := c.ResolutionDelay
	if resolutionDelay == 0 {
		resolutionDelay = defaultResolutionDelay
	}

	connectionAttemptDelay := c.ConnectionAttemptDelay
	switch {
	case connectionAttemptDelay == 0:
		connectionAttemptDelay = defaultConnectionAttemptDelay
	case connectionAttemptDelay < minimumConnectionAttemptDelay || connectionAttemptDelay > maximumConnectionAttemptDelay:
		return nil, fmt.Errorf("connection attempt delay %s out of range [%s, %s]", connectionAttemptDelay, minimumConnectionAttemptDelay, maximumConnectionAttemptDelay)
	}

	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return &TCPClient{
		name:                    c.Name,
		addressFamilyPreference: c.AddressFamilyPreference,
		resolutionDelay:         resolutionDelay,
		connectionAttemptDelay:  connectionAttemptDelay,
		localAddr4:              c.LocalAddr4,
		localAddr6:              c.LocalAddr6,
		dialer:                  c.Dialer,
		resolver:                resolver,
	}, nil
}

// TCPClient opens TCP connections and returns them directly.
//
// TCPClient implements [StreamClient] and [StreamDialer].
type TCPClient struct {
	name                    string
	addressFamilyPreference AddressFamilyPreference
	resolutionDelay         time.Duration
	connectionAttemptDelay  time.Duration
	localAddr4              netip.AddrPort
	localAddr6              netip.AddrPort
	dialer                  conn.TCPDialer
	resolver                conn.Resolver
}

var (
	_ StreamClient = (*TCPClient)(nil)
	_ StreamDialer = (*TCPClient)(nil)
)

// NewStreamDialer implements [StreamClient.NewStreamDialer].
func (c *TCPClient) NewStreamDialer() (StreamDialer, StreamDialerInfo) {
	return c, StreamDialerInfo{
		Name:                 c.name,
		NativeInitialPayload: c.dialer.TFO(),
	}
}

// DialStream implements [StreamDialer.DialStream].
func (c *TCPClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (Conn, error) {
	switch {
	case addr.IsIP():
		raddr := addr.IPPort()
		// TODO: Check address family preference and return an error that
		// can be parsed into a dial result with the correct error code.
		laddr := c.localAddr(raddr.Addr())
		return c.dialer.Dial(ctx, "tcp", laddr, raddr, payload)

	case addr.IsDomain():
		var lookupNetwork string
		switch c.addressFamilyPreference {
		case AddressFamilyPreferenceDefault:
			lookupNetwork = "ip"
		case AddressFamilyPreferencePreferIPv6:
			return c.resolveAndDialDomainWithResolutionDelay(ctx, "ip6", "ip4", addr.Domain(), addr.Port(), payload)
		case AddressFamilyPreferencePreferIPv4:
			return c.resolveAndDialDomainWithResolutionDelay(ctx, "ip4", "ip6", addr.Domain(), addr.Port(), payload)
		case AddressFamilyPreferenceIPv6Only:
			lookupNetwork = "ip6"
		case AddressFamilyPreferenceIPv4Only:
			lookupNetwork = "ip4"
		default:
			panic("unreachable")
		}
		return c.resolveAndDialDomain(ctx, lookupNetwork, addr.Domain(), addr.Port(), payload)

	default:
		return nil, conn.UnsupportedAddressKindErrorFromAddr(addr)
	}
}

// resolveAndDialDomain resolves the domain name to IP addresses of the specified network,
// and attempts to connect to them one at a time at intervals specified by the connection
// attempt delay. It returns the first successful connection, or all connection errors
// joined together if all attempts fail.
func (c *TCPClient) resolveAndDialDomain(ctx context.Context, network, domain string, port uint16, payload []byte) (Conn, error) {
	ips, err := c.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		return nil, err
	}

	attemptCtx, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()
	attemptCtxDone := attemptCtx.Done()

	resultCh := make(chan tcpDialResult)
	ticker := time.NewTicker(c.connectionAttemptDelay)
	var errs []error

	for _, ip := range ips {
		go func() {
			laddr := c.localAddr(ip)
			raddr := netip.AddrPortFrom(ip, port)
			tc, err := c.dialer.Dial(attemptCtx, "tcp", laddr, raddr, payload)
			select {
			case resultCh <- tcpDialResult{TCPConn: tc, Err: err}:
			case <-attemptCtxDone:
				if tc != nil {
					_ = tc.Close()
				}
			}
		}()

		select {
		case result := <-resultCh:
			if result.Err == nil {
				cancelAttempts()
				return result.TCPConn, nil
			}
			errs = append(errs, result.Err)
		case <-attemptCtxDone:
			return nil, attemptCtx.Err()
		case <-ticker.C:
		}
	}

	for len(errs) < len(ips) {
		select {
		case result := <-resultCh:
			if result.Err == nil {
				cancelAttempts()
				return result.TCPConn, nil
			}
			errs = append(errs, result.Err)
		case <-attemptCtxDone:
			return nil, attemptCtx.Err()
		}
	}

	return nil, fmt.Errorf("failed to connect to any IP: %w", errors.Join(errs...))
}

// resolveAndDialDomainWithResolutionDelay resolves the domain name to IP addresses of the
// preferred and secondary networks in parallel, starting connection attempts as soon as
// the preferred network's addresses are available, or after the resolution delay if the
// secondary network's addresses arrive first. It returns the first successful connection,
// or all connection errors joined together if all attempts fail.
func (c *TCPClient) resolveAndDialDomainWithResolutionDelay(
	ctx context.Context,
	preferredNetwork string,
	secondaryNetwork string,
	domain string,
	port uint16,
	payload []byte,
) (Conn, error) {
	type lookupResult struct {
		IPs       []netip.Addr
		Err       error
		Preferred bool
	}

	attemptCtx, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()
	attemptCtxDone := attemptCtx.Done()

	lookupResultCh := make(chan lookupResult)
	lookup := func(network string, preferred bool) {
		ips, err := c.resolver.LookupNetIP(attemptCtx, network, domain)
		select {
		case lookupResultCh <- lookupResult{IPs: ips, Err: err, Preferred: preferred}:
		case <-attemptCtxDone:
		}
	}
	go lookup(preferredNetwork, true)
	go lookup(secondaryNetwork, false)

	var (
		// lookupResultPrimary is the result of the preferred network lookup
		// if it arrives first or before the resolution delay timer fires,
		// otherwise it is the result of the secondary network lookup.
		lookupResultPrimary   lookupResult
		lookupResultSecondary lookupResult
		lookupSecondaryDone   bool
	)

	select {
	case lookupResultFirst := <-lookupResultCh:
		switch {
		case lookupResultFirst.Err != nil:
			// The first received result is an error, so the next one is our only shot now.
			// Block until we receive it or the context is done.
			select {
			case lookupResultPrimary = <-lookupResultCh:
				if lookupResultPrimary.Err != nil {
					return nil, fmt.Errorf("failed to resolve domain %q: %w", domain, errors.Join(lookupResultFirst.Err, lookupResultPrimary.Err))
				}
				lookupSecondaryDone = true
			case <-attemptCtxDone:
				return nil, attemptCtx.Err()
			}
		case lookupResultFirst.Preferred:
			// The first received result is successful and preferred. Happiest path.
			lookupResultPrimary = lookupResultFirst
		default:
			// We received a successful secondary result first.
			// The resolution delay applies here.
			select {
			case lookupResultPreferred := <-lookupResultCh:
				lookupResultPrimary = lookupResultPreferred
				lookupResultSecondary = lookupResultFirst
				lookupSecondaryDone = true
			case <-time.After(c.resolutionDelay):
				lookupResultPrimary = lookupResultFirst
			case <-attemptCtxDone:
				return nil, attemptCtx.Err()
			}
		}
	case <-attemptCtxDone:
		return nil, attemptCtx.Err()
	}

	resultCh := make(chan tcpDialResult)
	ticker := time.NewTicker(c.connectionAttemptDelay)
	var errs []error

	ips := func(yield func(netip.Addr) bool) {
		// Interleave primary and secondary IPs.
		for i, j := 0, 0; i < len(lookupResultPrimary.IPs) || j < len(lookupResultSecondary.IPs); {
			if i < len(lookupResultPrimary.IPs) {
				if !yield(lookupResultPrimary.IPs[i]) {
					return
				}
				i++
			}

			// If we haven't received the secondary lookup result yet,
			// attempt a non-blocking receive.
			if !lookupSecondaryDone {
				select {
				case lookupResultSecondary = <-lookupResultCh:
					lookupSecondaryDone = true
				default:
					continue
				}
			}

			if j < len(lookupResultSecondary.IPs) {
				if !yield(lookupResultSecondary.IPs[j]) {
					return
				}
				j++
			}
		}
	}

dial:
	for ip := range ips {
		go func() {
			laddr := c.localAddr(ip)
			raddr := netip.AddrPortFrom(ip, port)
			tc, err := c.dialer.Dial(attemptCtx, "tcp", laddr, raddr, payload)
			select {
			case resultCh <- tcpDialResult{TCPConn: tc, Err: err}:
			case <-attemptCtxDone:
				if tc != nil {
					_ = tc.Close()
				}
			}
		}()

		select {
		case result := <-resultCh:
			if result.Err == nil {
				cancelAttempts()
				return result.TCPConn, nil
			}
			errs = append(errs, result.Err)
		case <-attemptCtxDone:
			return nil, attemptCtx.Err()
		case <-ticker.C:
		}
	}

	if !lookupSecondaryDone {
		for {
			select {
			case result := <-resultCh:
				if result.Err == nil {
					cancelAttempts()
					return result.TCPConn, nil
				}
				errs = append(errs, result.Err)
			case lookupResultSecondary = <-lookupResultCh:
				ips = slices.Values(lookupResultSecondary.IPs)
				lookupSecondaryDone = true
				ticker.Reset(c.connectionAttemptDelay)
				goto dial
			case <-attemptCtxDone:
				return nil, attemptCtx.Err()
			}
		}
	}

	attempts := len(lookupResultPrimary.IPs) + len(lookupResultSecondary.IPs)
	for len(errs) < attempts {
		select {
		case result := <-resultCh:
			if result.Err == nil {
				cancelAttempts()
				return result.TCPConn, nil
			}
			errs = append(errs, result.Err)
		case <-attemptCtxDone:
			return nil, attemptCtx.Err()
		}
	}

	return nil, fmt.Errorf("failed to connect to any IP: %w", errors.Join(errs...))
}

type tcpDialResult struct {
	TCPConn *net.TCPConn
	Err     error
}

func (c *TCPClient) localAddr(ip netip.Addr) netip.AddrPort {
	if ip.Is4() || ip.Is4In6() {
		return c.localAddr4
	}
	return c.localAddr6
}

// NewTCPTransparentProxyServer returns a new TCP transparent proxy server.
func NewTCPTransparentProxyServer() (StreamServer, error) {
	return newTCPTransparentProxyServer()
}

// NewTCPRedirectServer returns a new TCP redirect server.
func NewTCPRedirectServer() (StreamServer, error) {
	return newTCPRedirectServer()
}

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

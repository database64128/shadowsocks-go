package conn

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"

	"github.com/database64128/tfo-go"
)

// ResolveAddr resolves a domain name string into netip.Addr.
// String representations of IP addresses are not supported.
func ResolveAddr(host string, preferIPv6 bool) (netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}

	// We can't actually do fallbacks here.
	// If preferIPv6 is true, v6 -> primaries, v4 -> fallbacks.
	// And vice versa.
	// Then we select a random IP from primaries, or fallbacks if primaries is empty.
	var primaries, fallbacks []netip.Addr

	for _, ip := range ips {
		switch {
		case preferIPv6 && !ip.Is4() && !ip.Is4In6() || !preferIPv6 && (ip.Is4() || ip.Is4In6()): // Prefer 6/4 and got 6/4
			primaries = append(primaries, ip)
		case preferIPv6 && (ip.Is4() || ip.Is4In6()) || !preferIPv6 && !ip.Is4() && !ip.Is4In6(): // Prefer 6/4 and got 4/6
			fallbacks = append(fallbacks, ip)
		default:
			return netip.Addr{}, errors.New("ip is neither 4 nor 6")
		}
	}

	var ip netip.Addr

	switch {
	case len(primaries) > 0:
		ip = primaries[rand.Intn(len(primaries))]
	case len(fallbacks) > 0:
		ip = fallbacks[rand.Intn(len(fallbacks))]
	default:
		return netip.Addr{}, errors.New("lookup returned no addresses and no error")
	}

	return ip, nil
}

// DialTFOWithPayload uses a TFO dialer to dial the target and writes the initial payload.
// TFO is disabled if initial payload is empty.
func DialTFOWithPayload(dialer *tfo.Dialer, address string, payload []byte) (n int, conn net.Conn, err error) {
	dialerDisableTFO := dialer.DisableTFO
	disableTFO := dialerDisableTFO || len(payload) == 0
	dialer.DisableTFO = disableTFO

	conn, err = dialer.Dial("tcp", address)
	if err != nil {
		return
	}

	if len(payload) > 0 {
		n, err = conn.Write(payload)
	}

	dialer.DisableTFO = dialerDisableTFO
	return
}

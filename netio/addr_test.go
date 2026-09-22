package netio_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/prefixset"
)

func TestResolveIPPort(t *testing.T) {
	for _, c := range [...]struct {
		name     string
		addr     conn.Addr
		pref     netio.AddressFamilyPreference
		resolver fakeResolver
		want     netip.AddrPort
	}{
		{
			name: "IPv6+AddressFamilyPreferenceDefault",
			addr: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80),
			pref: netio.AddressFamilyPreferenceDefault,
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "IPv6+AddressFamilyPreferencePreferIPv6",
			addr: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80),
			pref: netio.AddressFamilyPreferencePreferIPv6,
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "IPv6+AddressFamilyPreferencePreferIPv4",
			addr: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80),
			pref: netio.AddressFamilyPreferencePreferIPv4,
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "IPv6+AddressFamilyPreferenceIPv6Only",
			addr: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80),
			pref: netio.AddressFamilyPreferenceIPv6Only,
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "IPv4+AddressFamilyPreferenceDefault",
			addr: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
			pref: netio.AddressFamilyPreferenceDefault,
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "IPv4+AddressFamilyPreferencePreferIPv6",
			addr: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
			pref: netio.AddressFamilyPreferencePreferIPv6,
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "IPv4+AddressFamilyPreferencePreferIPv4",
			addr: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
			pref: netio.AddressFamilyPreferencePreferIPv4,
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "IPv4+AddressFamilyPreferenceIPv4Only",
			addr: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
			pref: netio.AddressFamilyPreferenceIPv4Only,
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "Domain+AddressFamilyPreferenceDefault",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferenceDefault,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "Domain+AddressFamilyPreferencePreferIPv6",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "Domain+AddressFamilyPreferencePreferIPv4",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "Domain+AddressFamilyPreferenceIPv6Only",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferenceIPv6Only,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "Domain+AddressFamilyPreferenceIPv4Only",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferenceIPv4Only,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := netio.ResolveIPPort(t.Context(), c.addr, c.pref, c.resolver)
			if err != nil {
				t.Fatalf("ResolveIPPort() error = %v", err)
			}
			if got != c.want {
				t.Errorf("ResolveIPPort() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolveIPPortError(t *testing.T) {
	expectAddressFamilyPreferenceMismatchError := func(wantPref netio.AddressFamilyPreference) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			e, ok := errors.AsType[netio.AddressFamilyPreferenceMismatchError](err)
			if !ok {
				t.Errorf("error = %v, want %T", err, e)
				return
			}
			if pref := netio.AddressFamilyPreference(e); pref != wantPref {
				t.Errorf("error preference = %v, want %v", pref, wantPref)
			}
		}
	}

	expectDNSErr := func(t *testing.T, err error) {
		if e, ok := errors.AsType[*net.DNSError](err); !ok {
			t.Errorf("error = %v, want %T", err, e)
		}
	}

	for _, c := range [...]struct {
		name     string
		addr     conn.Addr
		pref     netio.AddressFamilyPreference
		resolver fakeResolver
		checkErr func(*testing.T, error)
	}{
		{
			name:     "IPv6+AddressFamilyPreferenceIPv4Only",
			addr:     conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80),
			pref:     netio.AddressFamilyPreferenceIPv4Only,
			checkErr: expectAddressFamilyPreferenceMismatchError(netio.AddressFamilyPreferenceIPv4Only),
		},
		{
			name:     "IPv4+AddressFamilyPreferenceIPv6Only",
			addr:     conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
			pref:     netio.AddressFamilyPreferenceIPv6Only,
			checkErr: expectAddressFamilyPreferenceMismatchError(netio.AddressFamilyPreferenceIPv6Only),
		},
		{
			name:     "Domain+AddressFamilyPreferenceDefault",
			addr:     conn.MustAddrFromDomainPort("example.com", 80),
			checkErr: expectDNSErr,
		},
		{
			name: "Domain+AddressFamilyPreferenceIPv6Only",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferenceIPv6Only,
			resolver: fakeResolver{
				"example.com": {
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			checkErr: expectDNSErr,
		},
		{
			name: "Domain+AddressFamilyPreferenceIPv4Only",
			addr: conn.MustAddrFromDomainPort("example.com", 80),
			pref: netio.AddressFamilyPreferenceIPv4Only,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
				},
			},
			checkErr: expectDNSErr,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := netio.ResolveIPPort(t.Context(), c.addr, c.pref, c.resolver)
			c.checkErr(t, err)
			if got.IsValid() {
				t.Errorf("ResolveIPPort() = %v, want zero value", got)
			}
		})
	}
}

func TestResolveIPPortPreferredFirstFastReturn(t *testing.T) {
	for _, c := range [...]struct {
		name string
		pref netio.AddressFamilyPreference
		want netip.AddrPort
	}{
		{
			name: "PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// The resolver must be created inside the bubble to have its
				// channels associated with the bubble.
				resolver := newBlockingFakeResolver(fakeResolver{
					"example.com": {
						ip6: []netip.Addr{netip.IPv6Loopback()},
						ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
					},
				})

				// Without the wait group, t.Context() would be canceled as soon as
				// the main goroutine returns. t.Errorf() would then panic without
				// printing the message.
				var wg sync.WaitGroup
				wg.Go(func() {
					addr := conn.MustAddrFromDomainPort("example.com", 80)
					got, err := netio.ResolveIPPort(t.Context(), addr, c.pref, resolver)
					if err != nil {
						t.Errorf("ResolveIPPort() error = %v", err)
						return
					}
					if got != c.want {
						t.Errorf("ResolveIPPort() = %v, want %v", got, c.want)
					}
				})

				synctest.Wait()

				// Unblock preferred result.
				switch c.pref {
				case netio.AddressFamilyPreferencePreferIPv6:
					resolver.Unblock6()
				case netio.AddressFamilyPreferencePreferIPv4:
					resolver.Unblock4()
				default:
					t.Fatalf("unexpected address family preference: %v", c.pref)
				}

				wg.Wait()
			})
		})
	}
}

func TestResolveIPPortPreferredFirstErrorSlowReturn(t *testing.T) {
	for _, c := range [...]struct {
		name     string
		pref     netio.AddressFamilyPreference
		resolver fakeResolver
		want     netip.AddrPort
		wantErr  bool
	}{
		{
			name: "SecondarySuccess/PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "SecondarySuccess/PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "SecondaryError/PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {},
			},
			wantErr: true,
		},
		{
			name: "SecondaryError/PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {},
			},
			wantErr: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				resolver := newBlockingFakeResolver(c.resolver)

				var wg sync.WaitGroup
				wg.Go(func() {
					addr := conn.MustAddrFromDomainPort("example.com", 80)
					got, err := netio.ResolveIPPort(t.Context(), addr, c.pref, resolver)
					if err != nil != c.wantErr {
						t.Errorf("ResolveIPPort() error = %v", err)
						return
					}
					if got != c.want {
						t.Errorf("ResolveIPPort() = %v, want %v", got, c.want)
					}
				})

				synctest.Wait()

				// Unblock preferred result.
				switch c.pref {
				case netio.AddressFamilyPreferencePreferIPv6:
					resolver.Unblock6()
				case netio.AddressFamilyPreferencePreferIPv4:
					resolver.Unblock4()
				default:
					t.Fatalf("unexpected address family preference: %v", c.pref)
				}

				// Now waiting for the secondary result.
				synctest.Wait()

				// Unblock secondary result.
				switch c.pref {
				case netio.AddressFamilyPreferencePreferIPv6:
					resolver.Unblock4()
				case netio.AddressFamilyPreferencePreferIPv4:
					resolver.Unblock6()
				default:
					t.Fatalf("unexpected address family preference: %v", c.pref)
				}

				wg.Wait()
			})
		})
	}
}

func TestResolveIPPortSecondaryFirstSlowReturn(t *testing.T) {
	for _, c := range [...]struct {
		name     string
		pref     netio.AddressFamilyPreference
		resolver fakeResolver
		want     netip.AddrPort
		wantErr  bool
	}{
		{
			name: "SecondarySuccess/PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "SecondarySuccess/PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "SecondaryError/PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {
					ip6: []netip.Addr{netip.IPv6Loopback()},
				},
			},
			want: netip.AddrPortFrom(netip.IPv6Loopback(), 80),
		},
		{
			name: "SecondaryError/PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {
					ip4: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})},
				},
			},
			want: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 80),
		},
		{
			name: "PreferredError/PreferIPv6",
			pref: netio.AddressFamilyPreferencePreferIPv6,
			resolver: fakeResolver{
				"example.com": {},
			},
			wantErr: true,
		},
		{
			name: "PreferredError/PreferIPv4",
			pref: netio.AddressFamilyPreferencePreferIPv4,
			resolver: fakeResolver{
				"example.com": {},
			},
			wantErr: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				resolver := newBlockingFakeResolver(c.resolver)

				var wg sync.WaitGroup
				wg.Go(func() {
					addr := conn.MustAddrFromDomainPort("example.com", 80)
					got, err := netio.ResolveIPPort(t.Context(), addr, c.pref, resolver)
					if err != nil != c.wantErr {
						t.Errorf("ResolveIPPort() error = %v", err)
						return
					}
					if got != c.want {
						t.Errorf("ResolveIPPort() = %v, want %v", got, c.want)
					}
				})

				synctest.Wait()

				// Unblock secondary result first.
				switch c.pref {
				case netio.AddressFamilyPreferencePreferIPv6:
					resolver.Unblock4()
				case netio.AddressFamilyPreferencePreferIPv4:
					resolver.Unblock6()
				default:
					t.Fatalf("unexpected address family preference: %v", c.pref)
				}

				// Now waiting for the preferred result.
				synctest.Wait()

				// Unblock preferred result.
				switch c.pref {
				case netio.AddressFamilyPreferencePreferIPv6:
					resolver.Unblock6()
				case netio.AddressFamilyPreferencePreferIPv4:
					resolver.Unblock4()
				default:
					t.Fatalf("unexpected address family preference: %v", c.pref)
				}

				wg.Wait()
			})
		})
	}
}

type fakeResolver map[string]struct {
	ip6 []netip.Addr
	ip4 []netip.Addr
}

func (r fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	rec, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	var ips []netip.Addr
	switch network {
	case "ip":
		ips = slices.Concat(rec.ip6, rec.ip4)
	case "ip6":
		ips = rec.ip6
	case "ip4":
		ips = rec.ip4
	default:
		return nil, net.UnknownNetworkError(network)
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no suitable address found", Name: host}
	}
	return ips, nil
}

type blockingFakeResolver struct {
	records  fakeResolver
	unblock4 chan struct{}
	unblock6 chan struct{}
}

func newBlockingFakeResolver(records fakeResolver) blockingFakeResolver {
	return blockingFakeResolver{
		records:  records,
		unblock4: make(chan struct{}),
		unblock6: make(chan struct{}),
	}
}

func (r blockingFakeResolver) Unblock4() {
	close(r.unblock4)
}

func (r blockingFakeResolver) Unblock6() {
	close(r.unblock6)
}

func (r blockingFakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ctxDone := ctx.Done()
	switch network {
	case "ip":
		select {
		case <-ctxDone:
			return nil, ctx.Err()
		case <-r.unblock4:
		}

		select {
		case <-ctxDone:
			return nil, ctx.Err()
		case <-r.unblock6:
		}

	case "ip4":
		select {
		case <-ctxDone:
			return nil, ctx.Err()
		case <-r.unblock4:
		}

	case "ip6":
		select {
		case <-ctxDone:
			return nil, ctx.Err()
		case <-r.unblock6:
		}
	}
	return r.records.LookupNetIP(ctx, network, host)
}

func TestIPAllowDenyList(t *testing.T) {
	type checkIP struct {
		ip      netip.Addr
		wantErr error
	}

	for _, c := range [...]struct {
		name     string
		newACL   func() netio.IPAllowDenyList
		checkIPs []checkIP
	}{
		{
			name: "Empty",
			newACL: func() netio.IPAllowDenyList {
				return netio.IPAllowDenyList{}
			},
			checkIPs: []checkIP{
				{netip.Addr{}, nil},
				{netip.AddrFrom4([4]byte{127, 0, 0, 1}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}).WithZone("lo"), nil},
				{netip.IPv6Loopback(), nil},
				{netip.IPv6Loopback().WithZone("lo"), nil},
			},
		},
		{
			name: "Allowlist",
			newACL: func() netio.IPAllowDenyList {
				var allowlist prefixset.PrefixSet
				allowlist.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 32))
				allowlist.Insert(netip.PrefixFrom(netip.IPv6Loopback(), 128))
				return netio.IPAllowDenyList{
					Allowlist: &allowlist,
				}
			},
			checkIPs: []checkIP{
				{netip.Addr{}, netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom4([4]byte{127, 0, 0, 1}), nil},
				{netip.AddrFrom4([4]byte{127, 0, 0, 2}), netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}), netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}).WithZone("lo"), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}).WithZone("lo"), netio.AddrNotInAllowlistError{}},
				{netip.IPv6Loopback(), nil},
				{netip.IPv6Loopback().WithZone("lo"), nil},
				{netip.IPv6Loopback().Next(), netio.AddrNotInAllowlistError{}},
				{netip.IPv6Loopback().Next().WithZone("lo"), netio.AddrNotInAllowlistError{}},
			},
		},
		{
			name: "Denylist",
			newACL: func() netio.IPAllowDenyList {
				var denylist prefixset.PrefixSet
				denylist.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 32))
				denylist.Insert(netip.PrefixFrom(netip.IPv6Loopback(), 128))
				return netio.IPAllowDenyList{
					Denylist: &denylist,
				}
			},
			checkIPs: []checkIP{
				{netip.Addr{}, nil},
				{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netio.AddrInDenylistError{}},
				{netip.AddrFrom4([4]byte{127, 0, 0, 2}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), netio.AddrInDenylistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}).WithZone("lo"), netio.AddrInDenylistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}).WithZone("lo"), nil},
				{netip.IPv6Loopback(), netio.AddrInDenylistError{}},
				{netip.IPv6Loopback().WithZone("lo"), netio.AddrInDenylistError{}},
				{netip.IPv6Loopback().Next(), nil},
				{netip.IPv6Loopback().Next().WithZone("lo"), nil},
			},
		},
		{
			name: "Allowlist+Denylist",
			newACL: func() netio.IPAllowDenyList {
				var allowlist prefixset.PrefixSet
				allowlist.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8))
				allowlist.Insert(netip.PrefixFrom(netip.IPv6Loopback(), 64))
				var denylist prefixset.PrefixSet
				denylist.Insert(netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 2}), 32))
				denylist.Insert(netip.PrefixFrom(netip.IPv6Loopback().Next(), 128))
				return netio.IPAllowDenyList{
					Allowlist: &allowlist,
					Denylist:  &denylist,
				}
			},
			checkIPs: []checkIP{
				{netip.Addr{}, netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom4([4]byte{127, 0, 0, 1}), nil},
				{netip.AddrFrom4([4]byte{127, 0, 0, 2}), netio.AddrInDenylistError{}},
				{netip.AddrFrom4([4]byte{128, 0, 0, 1}), netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}), netio.AddrInDenylistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 128, 0, 0, 1}), netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}).WithZone("lo"), nil},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 2}).WithZone("lo"), netio.AddrInDenylistError{}},
				{netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 128, 0, 0, 1}).WithZone("lo"), netio.AddrNotInAllowlistError{}},
				{netip.IPv6Loopback(), nil},
				{netip.IPv6Loopback().WithZone("lo"), nil},
				{netip.IPv6Loopback().Next(), netio.AddrInDenylistError{}},
				{netip.IPv6Loopback().Next().WithZone("lo"), netio.AddrInDenylistError{}},
				{netip.AddrFrom16([16]byte{7: 0x01, 15: 0x01}), netio.AddrNotInAllowlistError{}},
				{netip.AddrFrom16([16]byte{7: 0x01, 15: 0x01}).WithZone("lo"), netio.AddrNotInAllowlistError{}},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			acl := c.newACL()
			for _, ipCheck := range c.checkIPs {
				if err := acl.Check(ipCheck.ip); err != ipCheck.wantErr {
					t.Errorf("acl.Check(%q) = %T, want %T", ipCheck.ip, err, ipCheck.wantErr)
				}
			}
		})
	}
}

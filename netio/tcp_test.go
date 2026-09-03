package netio_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/conntest"
	"github.com/database64128/shadowsocks-go/netio"
)

func TestTCPClientDialStreamDomainResolverError(t *testing.T) {
	addr := conn.MustAddrFromDomainPort("example.com", 80)
	ipErr := errors.New("lookup ip failed")
	ip6Err := errors.New("lookup ip6 failed")
	ip4Err := errors.New("lookup ip4 failed")
	resolver := brokenResolver{
		"ip":  ipErr,
		"ip6": ip6Err,
		"ip4": ip4Err,
	}

	for _, tc := range [...]struct {
		addressFamilyPreference netio.AddressFamilyPreference
		expectedErrs            []error
	}{
		{
			addressFamilyPreference: netio.AddressFamilyPreferenceDefault,
			expectedErrs:            []error{ipErr},
		},
		{
			addressFamilyPreference: netio.AddressFamilyPreferencePreferIPv6,
			expectedErrs:            []error{ip6Err, ip4Err},
		},
		{
			addressFamilyPreference: netio.AddressFamilyPreferencePreferIPv4,
			expectedErrs:            []error{ip4Err, ip6Err},
		},
		{
			addressFamilyPreference: netio.AddressFamilyPreferenceIPv6Only,
			expectedErrs:            []error{ip6Err},
		},
		{
			addressFamilyPreference: netio.AddressFamilyPreferenceIPv4Only,
			expectedErrs:            []error{ip4Err},
		},
	} {
		t.Run(tc.addressFamilyPreference.String(), func(t *testing.T) {
			clientConfig := netio.TCPClientConfig{
				Name:                    "test",
				AddressFamilyPreference: tc.addressFamilyPreference,
				Dialer:                  conntest.DefaultTCPDialer(),
				Resolver:                resolver,
			}
			client, err := clientConfig.NewTCPClient()
			if err != nil {
				t.Fatalf("Failed to create TCP client: %v", err)
			}

			if _, err = client.DialStream(t.Context(), addr, nil); err == nil {
				t.Fatal("client.DialStream() did not return an error")
			}

			for _, expectedErr := range tc.expectedErrs {
				if !errors.Is(err, expectedErr) {
					t.Errorf("client.DialStream() error = %v, want %v", err, expectedErr)
				}
			}
		})
	}
}

type brokenResolver map[string]error

func (r brokenResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return nil, r[network]
}

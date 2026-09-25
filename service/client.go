package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/httpproxy"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/ssnone"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// ClientConfig is the configuration for a client.
type ClientConfig struct {
	// Name is the name of the client.
	Name string `json:"name"`

	// Protocol is the protocol used by the client.
	//
	//  - "direct": Direct connection.
	//  - "socks5": SOCKS5 proxy.
	//  - "http": HTTP proxy.
	//  - "none", "plain": Shadowsocks "none" proxy.
	//  - "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm": Shadowsocks 2022 proxy.
	Protocol string `json:"protocol"`

	// This field is obsolete and will be removed in a future release.
	//
	//  - "ip": Override AddressFamilyPreference to "default".
	//  - "ip4": Override AddressFamilyPreference to "ipv4-only".
	//  - "ip6": Override AddressFamilyPreference to "ipv6-only".
	Network string `json:"network,omitzero"`

	// Endpoint is the address of the remote proxy server, if applicable.
	//
	// Do not use if either TCPAddress or UDPAddress is specified.
	Endpoint conn.Addr `json:"endpoint,omitzero"`

	// TCPAddress is the TCP address of the remote proxy server, if applicable.
	//
	// Do not use if Endpoint is specified.
	TCPAddress conn.Addr `json:"tcpAddress,omitzero"`

	// UDPAddress is the UDP address of the remote proxy server, if applicable.
	//
	// Do not use if Endpoint is specified.
	UDPAddress conn.Addr `json:"udpAddress,omitzero"`

	// AddressFamilyPreference specifies the preference for IPv4 or IPv6 addresses.
	//
	//  - "default": Follow the system default.
	//  - "prefer-ipv6": Prefer IPv6 addresses.
	//  - "prefer-ipv4": Prefer IPv4 addresses.
	//  - "ipv6-only": Use only IPv6 addresses.
	//  - "ipv4-only": Use only IPv4 addresses.
	//
	// If unspecified, "default" is used.
	//
	// For more details on the exact behavior of each setting, refer to the protocol client's documentation.
	AddressFamilyPreference netio.AddressFamilyPreference `json:"addressFamilyPreference,omitzero"`

	// ResolutionDelay specifies the resolution delay for the TCP client's Happy Eyeballs v3 algorithm.
	//
	// See [netio.TCPClientConfig.ResolutionDelay] for more details.
	ResolutionDelay jsoncfg.Duration `json:"resolutionDelay,omitzero"`

	// ConnectionAttemptDelay specifies the connection attempt delay for the TCP client's Happy Eyeballs v3 algorithm.
	//
	// See [netio.TCPClientConfig.ConnectionAttemptDelay] for more details.
	ConnectionAttemptDelay jsoncfg.Duration `json:"connectionAttemptDelay,omitzero"`

	// LocalAddr4 specifies an optional local IPv4 address and port to bind to for IPv4 traffic.
	//
	// As of the current implementation, this only applies to outgoing TCP connections.
	LocalAddr4 netip.AddrPort `json:"localAddr4,omitzero"`

	// LocalAddr6 specifies an optional local IPv6 address and port to bind to for IPv6 traffic.
	//
	// As of the current implementation, this only applies to outgoing TCP connections.
	LocalAddr6 netip.AddrPort `json:"localAddr6,omitzero"`

	// IPAllowlistPrefixes specifies the IP address prefixes to include in the destination IP address allowlist.
	IPAllowlistPrefixes []netip.Prefix `json:"ipAllowlistPrefixes,omitzero"`

	// IPAllowlistPrefixSets specifies the names of prefix sets to include in the destination IP address allowlist.
	//
	// Specifying a single prefix set name is the most efficient way to build the allowlist.
	IPAllowlistPrefixSets []string `json:"ipAllowlistPrefixSets,omitzero"`

	// IPDenylistPrefixes specifies the IP address prefixes to include in the destination IP address denylist.
	IPDenylistPrefixes []netip.Prefix `json:"ipDenylistPrefixes,omitzero"`

	// IPDenylistPrefixSets specifies the names of prefix sets to include in the destination IP address denylist.
	//
	// Specifying a single prefix set name is the most efficient way to build the denylist.
	IPDenylistPrefixSets []string `json:"ipDenylistPrefixSets,omitzero"`

	// OverrideResolverDialAddress optionally specifies an alternate DNS server address
	// to override the dial address of the dialer's DNS resolver.
	OverrideResolverDialAddress string `json:"overrideResolverDialAddress,omitzero"`

	// DialerFwmark sets the dialer's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	DialerFwmark int `json:"dialerFwmark,omitzero"`

	// DialerTrafficClass sets the traffic class of the dialer.
	//
	// Available on most platforms except Windows.
	DialerTrafficClass int `json:"dialerTrafficClass,omitzero"`

	// EnableTCP controls whether to enable TCP on the client.
	EnableTCP bool `json:"enableTCP,omitzero"`

	// TCPPathMTUDiscovery specifies the Path MTU Discovery mode for TCP sockets.
	//
	// The default is [PMTUDModeAppDefault], which follows the system default.
	TCPPathMTUDiscovery PMTUDMode `json:"tcpPathMTUDiscovery,omitzero"`

	// DialerTFO enables TCP Fast Open on the dialer.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	DialerTFO bool `json:"dialerTFO,omitzero"`

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the dialer.
	//
	// When enabled, the dialer will connect without TFO if TFO is not available on the system.
	// When disabled, the dialer will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool `json:"tcpFastOpenFallback,omitzero"`

	// MultipathTCP enables multipath TCP on the client.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	MultipathTCP bool `json:"multipathTCP,omitzero"`

	// AllowSegmentedFixedLengthHeader disables the requirement that
	// the fixed-length header must be read in a single read call.
	//
	// This option is useful when the underlying stream transport
	// does not exhibit typical TCP behavior.
	//
	// Only applicable to Shadowsocks 2022 TCP.
	AllowSegmentedFixedLengthHeader bool `json:"allowSegmentedFixedLengthHeader,omitzero"`

	// EnableUDP controls whether to enable UDP on the client.
	EnableUDP bool `json:"enableUDP,omitzero"`

	// UDPPathMTUDiscovery specifies the Path MTU Discovery mode for UDP sockets.
	//
	// The default is [PMTUDModeAppDefault], which disables IP fragmentation for better performance and reliability.
	UDPPathMTUDiscovery PMTUDMode `json:"udpPathMTUDiscovery,omitzero"`

	// MTU is the MTU of the client's designated network path.
	MTU int `json:"mtu,omitzero"`

	// Socks5 is the protocol-specific configuration for "socks5".
	Socks5 Socks5ClientConfig `json:"socks5,omitzero"`

	// HTTP is the protocol-specific configuration for "http".
	HTTP HTTPProxyClientConfig `json:"http,omitzero"`

	// PSK specifies the pre-shared key (PSK) in single-user mode,
	// or the user pre-shared key (uPSK) in multi-user mode for Shadowsocks 2022.
	PSK []byte `json:"psk,omitzero"`

	// IPSKs specifies the identity pre-shared keys (iPSKs) for Shadowsocks 2022.
	//
	// Leave empty for single-user servers.
	IPSKs [][]byte `json:"iPSKs,omitzero"`

	// PaddingPolicy specifies the padding policy for Shadowsocks 2022 packets.
	//
	//  - "PadPlainDNS": Only add padding if the destination port is 53. (default)
	//  - "PadAll": Always add padding.
	//  - "NoPadding": Never add padding.
	PaddingPolicy ss2022.PaddingPolicyField `json:"paddingPolicy,omitzero"`

	// SlidingWindowFilterSize is the size of the sliding window filter.
	//
	// The default value is 256.
	//
	// Only applicable to Shadowsocks 2022 UDP.
	SlidingWindowFilterSize uint64 `json:"slidingWindowFilterSize,omitzero"`

	// UnsafeRequestStreamPrefix specifies the prefix bytes to prepend to Shadowsocks 2022 request streams.
	UnsafeRequestStreamPrefix []byte `json:"unsafeRequestStreamPrefix,omitzero"`

	// UnsafeResponseStreamPrefix specifies the prefix bytes to prepend to Shadowsocks 2022 response streams.
	UnsafeResponseStreamPrefix []byte `json:"unsafeResponseStreamPrefix,omitzero"`
}

func (c *ClientConfig) checkAddresses() (tcpAddr, udpAddr conn.Addr, err error) {
	if c.Protocol == "direct" {
		return conn.Addr{}, conn.Addr{}, nil
	}

	ev := c.Endpoint.IsValid()
	tv := c.TCPAddress.IsValid()
	uv := c.UDPAddress.IsValid()

	if ev == (tv || uv) {
		return conn.Addr{}, conn.Addr{}, errors.New("missing or conflicting proxy server address(es)")
	}

	if ev {
		return c.Endpoint, c.Endpoint, nil
	}

	if c.EnableTCP && !tv {
		return conn.Addr{}, conn.Addr{}, errors.New("missing proxy server TCP address")
	}

	if c.EnableUDP && !uv {
		return conn.Addr{}, conn.Addr{}, errors.New("missing proxy server UDP address")
	}

	return c.TCPAddress, c.UDPAddress, nil
}

// AddClient creates a client from the configuration and adds it to the client maps.
func (c *ClientConfig) AddClient(
	streamClientByName map[string]netio.StreamClient,
	udpClientByName map[string]zerocopy.UDPClient,
	tcpDialerCache conn.TCPDialerCache,
	udpSocketConfigCache conn.UDPSocketConfigCache,
	prefixSetByName map[string]*prefixset.PrefixSet,
	tlsCertStore *tlscerts.Store,
	logger *tslog.Logger,
) error {
	if !c.EnableTCP && !c.EnableUDP {
		return nil
	}

	if c.EnableUDP && c.MTU < minimumMTU {
		return ErrMTUTooSmall
	}

	if c.Network != "" {
		if c.AddressFamilyPreference == netio.AddressFamilyPreferenceDefault {
			switch c.Network {
			case "ip":
			case "ip6":
				c.AddressFamilyPreference = netio.AddressFamilyPreferenceIPv6Only
			case "ip4":
				c.AddressFamilyPreference = netio.AddressFamilyPreferenceIPv4Only
			default:
				return fmt.Errorf("unknown network: %q", c.Network)
			}
		}
		logger.Warn("network is obsolete and will be removed in a future release; migrate to addressFamilyPreference for more granular control",
			slog.String("client", c.Name),
		)
	}

	tcpAddr, udpAddr, err := c.checkAddresses()
	if err != nil {
		return err
	}

	var resolver conn.Resolver
	if c.OverrideResolverDialAddress != "" {
		tcpDialer := c.tcpDialer(tcpDialerCache)
		udpSocketConfig := c.udpSocketConfig(udpSocketConfigCache)
		resolverDialer := conn.NewDialer(tcpDialer, udpSocketConfig, conn.UnixDomainSocketConfig{})
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return resolverDialer.Dial(ctx, network, c.OverrideResolverDialAddress)
			},
		}
	}

	var ipACL netio.IPAllowDenyList
	if len(c.IPAllowlistPrefixes) > 0 || len(c.IPAllowlistPrefixSets) > 0 {
		allowlist, err := prefixset.FromPrefixesAndPrefixSetNames(c.IPAllowlistPrefixes, c.IPAllowlistPrefixSets, prefixSetByName)
		if err != nil {
			return fmt.Errorf("failed to assemble IP allowlist: %w", err)
		}
		ipACL.Allowlist = allowlist
	}
	if len(c.IPDenylistPrefixes) > 0 || len(c.IPDenylistPrefixSets) > 0 {
		denylist, err := prefixset.FromPrefixesAndPrefixSetNames(c.IPDenylistPrefixes, c.IPDenylistPrefixSets, prefixSetByName)
		if err != nil {
			return fmt.Errorf("failed to assemble IP denylist: %w", err)
		}
		ipACL.Denylist = denylist
	}

	switch c.Protocol {
	case "direct":
		if c.EnableTCP {
			streamClient, err := c.innerTCPClient(tcpDialerCache, resolver, ipACL)
			if err != nil {
				return err
			}
			streamClientByName[c.Name] = streamClient
		}

		if c.EnableUDP {
			udpClientByName[c.Name] = direct.NewDirectUDPClient(c.Name, c.AddressFamilyPreference, resolver, ipACL, c.MTU, c.udpSocketConfig(udpSocketConfigCache))
		}

	case "none", "plain":
		if c.EnableTCP {
			innerClient, err := c.innerTCPClient(tcpDialerCache, resolver, ipACL)
			if err != nil {
				return err
			}

			cfg := ssnone.StreamClientConfig{
				Name:        c.Name,
				InnerClient: innerClient,
				Addr:        tcpAddr,
			}
			streamClientByName[c.Name] = cfg.NewStreamClient()
		}

		if c.EnableUDP {
			udpClientByName[c.Name] = direct.NewShadowsocksNoneUDPClient(c.Name, udpAddr, c.AddressFamilyPreference, resolver, c.MTU, c.udpSocketConfig(udpSocketConfigCache))
		}

	case "socks5":
		innerClient, err := c.innerTCPClient(tcpDialerCache, resolver, ipACL)
		if err != nil {
			return err
		}

		var authMsg []byte
		if c.Socks5.EnableUserPassAuth {
			if err := c.Socks5.Validate(); err != nil {
				return fmt.Errorf("bad user credentials: %w", err)
			}
			authMsg = c.Socks5.AppendAuthMsg(nil)
		}

		if c.EnableTCP {
			cfg := socks5.StreamClientConfig{
				Name:        c.Name,
				InnerClient: innerClient,
				Addr:        tcpAddr,
				AuthMsg:     authMsg,
			}
			streamClientByName[c.Name] = cfg.NewStreamClient()
		}

		if c.EnableUDP {
			cfg := direct.Socks5UDPClientConfig{
				Logger:                  logger,
				Name:                    c.Name,
				StreamDialer:            innerClient,
				Addr:                    udpAddr,
				AddressFamilyPreference: c.AddressFamilyPreference,
				Resolver:                resolver,
				MTU:                     c.MTU,
				SocketConfig:            c.udpSocketConfig(udpSocketConfigCache),
				AuthMsg:                 authMsg,
			}
			udpClientByName[c.Name] = cfg.NewClient()
		}

	case "http":
		if c.EnableUDP {
			return errors.New("HTTP proxy does not support UDP")
		}

		innerClient, err := c.innerTCPClient(tcpDialerCache, resolver, ipACL)
		if err != nil {
			return err
		}

		serverName := c.HTTP.ServerName
		if c.HTTP.UseTLS && serverName == "" {
			serverName = tcpAddr.Host()
		}

		cfg := httpproxy.ClientConfig{
			Name:                           c.Name,
			InnerClient:                    innerClient,
			Addr:                           tcpAddr,
			ServerName:                     serverName,
			EncryptedClientHelloConfigList: c.HTTP.ECHConfigList,
			Username:                       c.HTTP.Username,
			Password:                       c.HTTP.Password,
			UseTLS:                         c.HTTP.UseTLS,
			UseBasicAuth:                   c.HTTP.UseBasicAuth,
		}

		if c.HTTP.CertList != "" {
			certList, ok := tlsCertStore.GetCertList(c.HTTP.CertList)
			if !ok {
				return fmt.Errorf("certificate list not found: %q", c.HTTP.CertList)
			}
			cfg.Certificates, cfg.GetClientCertificate = certList.GetClientCertificateFunc()
		}

		if c.HTTP.RootCAs != "" {
			pool, ok := tlsCertStore.GetX509CertPool(c.HTTP.RootCAs)
			if !ok {
				return fmt.Errorf("root CA X.509 certificate pool not found: %q", c.HTTP.RootCAs)
			}
			cfg.RootCAs = pool
		}

		streamClient, err := cfg.NewProxyClient()
		if err != nil {
			return err
		}
		streamClientByName[c.Name] = streamClient

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if err := ss2022.CheckPSKLength(c.Protocol, c.PSK, c.IPSKs); err != nil {
			return err
		}
		cipherConfig, err := ss2022.NewClientCipherConfig(c.PSK, c.IPSKs, c.EnableUDP)
		if err != nil {
			return err
		}

		if c.EnableTCP {
			innerClient, err := c.innerTCPClient(tcpDialerCache, resolver, ipACL)
			if err != nil {
				return err
			}

			cfg := ss2022.StreamClientConfig{
				Name:                            c.Name,
				InnerClient:                     innerClient,
				Addr:                            tcpAddr,
				AllowSegmentedFixedLengthHeader: c.AllowSegmentedFixedLengthHeader,
				CipherConfig:                    cipherConfig,
				UnsafeRequestStreamPrefix:       c.UnsafeRequestStreamPrefix,
				UnsafeResponseStreamPrefix:      c.UnsafeResponseStreamPrefix,
			}
			streamClientByName[c.Name] = cfg.NewStreamClient()
		}

		if c.EnableUDP {
			udpClientByName[c.Name] = ss2022.NewUDPClient(c.Name, udpAddr, c.AddressFamilyPreference, resolver, c.MTU, c.udpSocketConfig(udpSocketConfigCache), c.SlidingWindowFilterSize, cipherConfig, c.PaddingPolicy.Policy())
		}

	default:
		return fmt.Errorf("unknown protocol: %q", c.Protocol)
	}

	return nil
}

func (c *ClientConfig) innerTCPClient(tcpDialerCache conn.TCPDialerCache, resolver conn.Resolver, ipACL netio.IPAllowDenyList) (*netio.TCPClient, error) {
	tcc := netio.TCPClientConfig{
		Name:                    c.Name,
		AddressFamilyPreference: c.AddressFamilyPreference,
		ResolutionDelay:         c.ResolutionDelay.Value(),
		ConnectionAttemptDelay:  c.ConnectionAttemptDelay.Value(),
		LocalAddr4:              c.LocalAddr4,
		LocalAddr6:              c.LocalAddr6,
		Dialer:                  c.tcpDialer(tcpDialerCache),
		Resolver:                resolver,
		IPAllowDenyList:         ipACL,
	}
	return tcc.NewTCPClient()
}

func (c *ClientConfig) tcpDialer(tcpDialerCache conn.TCPDialerCache) conn.TCPDialer {
	return tcpDialerCache.Get(conn.TCPConnectSocketOptions{
		Fwmark:       c.DialerFwmark,
		TrafficClass: c.DialerTrafficClass,
		// Unconditionally set to true as a workaround for https://github.com/golang/go/issues/81620.
		// Once we upgrade to a Go version with the fix, set to c.LocalAddr4.IsValid() || c.LocalAddr6.IsValid().
		BindAddressNoPort:   true,
		PathMTUDiscovery:    c.TCPPathMTUDiscovery.TCP(),
		TCPFastOpen:         c.DialerTFO,
		TCPFastOpenFallback: c.TCPFastOpenFallback,
		MultipathTCP:        c.MultipathTCP,
	})
}

func (c *ClientConfig) udpSocketConfig(udpSocketConfigCache conn.UDPSocketConfigCache) conn.UDPSocketConfig {
	return udpSocketConfigCache.Get(conn.UDPSocketOptions{
		SendBufferSize:    conn.DefaultUDPSocketBufferSize,
		ReceiveBufferSize: conn.DefaultUDPSocketBufferSize,
		Fwmark:            c.DialerFwmark,
		TrafficClass:      c.DialerTrafficClass,
		PathMTUDiscovery:  c.UDPPathMTUDiscovery.UDP(),
	})
}

// Socks5ClientConfig is the configuration for a SOCKS5 client.
type Socks5ClientConfig struct {
	// UserInfo is a username/password pair for authentication.
	socks5.UserInfo

	// EnableUserPassAuth controls whether to enable username/password authentication.
	EnableUserPassAuth bool `json:"enableUserPassAuth,omitzero"`
}

// HTTPProxyClientConfig is the configuration for an HTTP proxy client.
type HTTPProxyClientConfig struct {
	// CertList is the name of the certificate list in the certificate store,
	// used as the client certificate for mutual TLS.
	// If empty, no client certificate is used.
	CertList string `json:"certList,omitzero"`

	// RootCAs is the name of the X.509 certificate pool in the certificate store,
	// used for verifying the server certificate.
	// If empty, the system default is used.
	RootCAs string `json:"rootCAs,omitzero"`

	// ServerName is the server name used for TLS.
	// If empty, it is inferred from the address.
	ServerName string `json:"serverName,omitzero"`

	// ECHConfigList is a serialized ECHConfigList.
	// See [tls.Config.EncryptedClientHelloConfigList].
	ECHConfigList []byte `json:"echConfigList,omitzero"`

	// Username is the username used for authentication.
	Username string `json:"username,omitzero"`

	// Password is the password used for authentication.
	Password string `json:"password,omitzero"`

	// UseTLS controls whether to use TLS.
	UseTLS bool `json:"useTLS,omitzero"`

	// UseBasicAuth controls whether to use HTTP Basic Authentication.
	UseBasicAuth bool `json:"useBasicAuth,omitzero"`
}

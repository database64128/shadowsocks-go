package service

import (
	"errors"
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/httpproxy"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/ssnone"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ClientConfig stores a client configuration.
// It may be marshaled as or unmarshaled from JSON.
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

	// Network controls the address family of the resolved IP address
	// when the address is a domain name. It is ignored if the address
	// is an IP address.
	//
	//  - "ip": Follow the system default.
	//  - "ip4": Resolve to an IPv4 address.
	//  - "ip6": Resolve to an IPv6 address.
	//
	// If unspecified, "ip" is used.
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

	// AllowFragmentation controls whether to allow fragmented UDP packets.
	//
	// IP fragmentation does not reliably work over the Internet.
	// Sending fragmented packets will significantly reduce throughput.
	// Do not enable this option unless it is absolutely necessary.
	AllowFragmentation bool `json:"allowFragmentation,omitzero"`

	// MTU is the MTU of the client's designated network path.
	MTU int `json:"mtu,omitzero"`

	// Socks5 is the protocol-specific configuration for "socks5".
	Socks5 Socks5ClientConfig `json:"socks5,omitzero"`

	socks5AuthMsg []byte

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

	cipherConfig *ss2022.ClientCipherConfig

	// UnsafeRequestStreamPrefix specifies the prefix bytes to prepend to Shadowsocks 2022 request streams.
	//
	// The use of this feature "taints" the client.
	UnsafeRequestStreamPrefix []byte `json:"unsafeRequestStreamPrefix,omitzero"`

	// UnsafeResponseStreamPrefix specifies the prefix bytes to prepend to Shadowsocks 2022 response streams.
	//
	// The use of this feature "taints" the client.
	UnsafeResponseStreamPrefix []byte `json:"unsafeResponseStreamPrefix,omitzero"`

	tlsCertStore      *tlscerts.Store
	listenConfigCache conn.ListenConfigCache
	dialerCache       conn.DialerCache
	logger            *zap.Logger

	networkTCP  string
	connDialer  conn.Dialer
	innerClient *netio.TCPClient
}

func (cc *ClientConfig) checkAddresses() error {
	if cc.Protocol == "direct" {
		return nil
	}

	ev := cc.Endpoint.IsValid()
	tv := cc.TCPAddress.IsValid()
	uv := cc.UDPAddress.IsValid()

	if ev == (tv || uv) {
		return errors.New("missing or conflicting proxy server address(es)")
	}

	if ev {
		cc.TCPAddress = cc.Endpoint
		cc.UDPAddress = cc.Endpoint
		return nil
	}

	if cc.EnableTCP && !tv {
		return errors.New("missing proxy server TCP address")
	}

	if cc.EnableUDP && !uv {
		return errors.New("missing proxy server UDP address")
	}

	return nil
}

// Initialize initializes the client configuration.
func (cc *ClientConfig) Initialize(tlsCertStore *tlscerts.Store, listenConfigCache conn.ListenConfigCache, dialerCache conn.DialerCache, logger *zap.Logger) (err error) {
	switch cc.Network {
	case "":
		cc.Network = "ip"
	case "ip", "ip4", "ip6":
	default:
		return fmt.Errorf("unknown network: %q", cc.Network)
	}

	if err = cc.checkAddresses(); err != nil {
		return
	}

	switch cc.Protocol {
	case "socks5":
		if cc.Socks5.EnableUserPassAuth {
			if err = cc.Socks5.Validate(); err != nil {
				return fmt.Errorf("bad user credentials: %w", err)
			}
			cc.socks5AuthMsg = cc.Socks5.AppendAuthMsg(nil)
		}

	case "http":
		if cc.HTTP.UseTLS && cc.HTTP.ServerName == "" {
			cc.HTTP.ServerName = cc.TCPAddress.Host()
		}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if err = ss2022.CheckPSKLength(cc.Protocol, cc.PSK, cc.IPSKs); err != nil {
			return
		}
		cc.cipherConfig, err = ss2022.NewClientCipherConfig(cc.PSK, cc.IPSKs, cc.EnableUDP)
		if err != nil {
			return
		}
	}

	cc.tlsCertStore = tlsCertStore
	cc.listenConfigCache = listenConfigCache
	cc.dialerCache = dialerCache
	cc.logger = logger

	if cc.EnableTCP || cc.EnableUDP && cc.Protocol == "socks5" {
		cc.networkTCP = cc.tcpNetwork()
		cc.connDialer = cc.dialer()
		cc.innerClient = cc.newInnerClient()
	}

	return nil
}

func (cc *ClientConfig) tcpNetwork() string {
	switch cc.Network {
	case "ip":
		return "tcp"
	case "ip4":
		return "tcp4"
	case "ip6":
		return "tcp6"
	default:
		panic("unreachable")
	}
}

func (cc *ClientConfig) dialer() conn.Dialer {
	return cc.dialerCache.Get(conn.DialerSocketOptions{
		Fwmark:              cc.DialerFwmark,
		TrafficClass:        cc.DialerTrafficClass,
		TCPFastOpen:         cc.DialerTFO,
		TCPFastOpenFallback: cc.TCPFastOpenFallback,
		MultipathTCP:        cc.MultipathTCP,
	})
}

func (cc *ClientConfig) newInnerClient() *netio.TCPClient {
	tcc := netio.TCPClientConfig{
		Name:    cc.Name,
		Network: cc.networkTCP,
		Dialer:  cc.connDialer,
	}
	return tcc.NewTCPClient()
}

// TCPClient returns a new [netio.StreamClient] from the configuration.
func (cc *ClientConfig) TCPClient() (netio.StreamClient, error) {
	if !cc.EnableTCP {
		return nil, errNetworkDisabled
	}

	switch cc.Protocol {
	case "direct":
		return cc.innerClient, nil

	case "none", "plain":
		scc := ssnone.StreamClientConfig{
			Name:        cc.Name,
			InnerClient: cc.innerClient,
			Addr:        cc.TCPAddress,
		}
		return scc.NewStreamClient(), nil

	case "socks5":
		scc := socks5.StreamClientConfig{
			Name:        cc.Name,
			InnerClient: cc.innerClient,
			Addr:        cc.TCPAddress,
			AuthMsg:     cc.socks5AuthMsg,
		}
		return scc.NewStreamClient(), nil

	case "http":
		hpcc := httpproxy.ClientConfig{
			Name:                           cc.Name,
			InnerClient:                    cc.innerClient,
			Addr:                           cc.TCPAddress,
			ServerName:                     cc.HTTP.ServerName,
			EncryptedClientHelloConfigList: cc.HTTP.ECHConfigList,
			Username:                       cc.HTTP.Username,
			Password:                       cc.HTTP.Password,
			UseTLS:                         cc.HTTP.UseTLS,
			UseBasicAuth:                   cc.HTTP.UseBasicAuth,
		}

		if cc.HTTP.CertList != "" {
			certList, ok := cc.tlsCertStore.GetCertList(cc.HTTP.CertList)
			if !ok {
				return nil, fmt.Errorf("certificate list not found: %q", cc.HTTP.CertList)
			}
			hpcc.Certificates, hpcc.GetClientCertificate = certList.GetClientCertificateFunc()
		}

		if cc.HTTP.RootCAs != "" {
			pool, ok := cc.tlsCertStore.GetX509CertPool(cc.HTTP.RootCAs)
			if !ok {
				return nil, fmt.Errorf("root CA X.509 certificate pool not found: %q", cc.HTTP.RootCAs)
			}
			hpcc.RootCAs = pool
		}

		return hpcc.NewProxyClient()

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if len(cc.UnsafeRequestStreamPrefix) != 0 || len(cc.UnsafeResponseStreamPrefix) != 0 {
			cc.logger.Warn("Unsafe stream prefix taints the client", zap.String("client", cc.Name))
		}

		scc := ss2022.StreamClientConfig{
			Name:                            cc.Name,
			InnerClient:                     cc.innerClient,
			Addr:                            cc.TCPAddress,
			AllowSegmentedFixedLengthHeader: cc.AllowSegmentedFixedLengthHeader,
			CipherConfig:                    cc.cipherConfig,
			UnsafeRequestStreamPrefix:       cc.UnsafeRequestStreamPrefix,
			UnsafeResponseStreamPrefix:      cc.UnsafeResponseStreamPrefix,
		}
		return scc.NewStreamClient(), nil

	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
}

func (cc *ClientConfig) UDPClient() (zerocopy.UDPClient, error) {
	if !cc.EnableUDP {
		return nil, errNetworkDisabled
	}

	if cc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	listenConfig := cc.listenConfigCache.Get(conn.ListenerSocketOptions{
		SendBufferSize:    conn.DefaultUDPSocketBufferSize,
		ReceiveBufferSize: conn.DefaultUDPSocketBufferSize,
		Fwmark:            cc.DialerFwmark,
		TrafficClass:      cc.DialerTrafficClass,
		PathMTUDiscovery:  !cc.AllowFragmentation,
	})

	switch cc.Protocol {
	case "direct":
		return direct.NewDirectUDPClient(cc.Name, cc.Network, cc.MTU, listenConfig), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneUDPClient(cc.Name, cc.Network, cc.UDPAddress, cc.MTU, listenConfig), nil
	case "socks5":
		s5ucc := direct.Socks5UDPClientConfig{
			Logger:       cc.logger,
			Name:         cc.Name,
			NetworkTCP:   cc.networkTCP,
			NetworkIP:    cc.Network,
			Address:      cc.UDPAddress.String(),
			Dialer:       cc.connDialer,
			MTU:          cc.MTU,
			ListenConfig: listenConfig,
			AuthMsg:      cc.socks5AuthMsg,
		}
		return s5ucc.NewClient(), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return ss2022.NewUDPClient(cc.Name, cc.Network, cc.UDPAddress, cc.MTU, listenConfig, cc.SlidingWindowFilterSize, cc.cipherConfig, cc.PaddingPolicy.Policy()), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
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

package service

import (
	"errors"
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/httpproxy"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/ss2022"
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
	// Valid values include "direct", "socks5", "http", "none", "plain", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm".
	Protocol string `json:"protocol"`

	// Network controls the address family of the resolved IP address
	// when the address is a domain name. It is ignored if the address
	// is an IP address.
	//
	// - "ip": Follow the system default.
	// - "ip4": Resolve to an IPv4 address.
	// - "ip6": Resolve to an IPv6 address.
	//
	// If unspecified, "ip" is used.
	Network string `json:"network"`

	// Endpoint is the address of the remote proxy server, if applicable.
	//
	// Do not use if either TCPAddress or UDPAddress is specified.
	Endpoint conn.Addr `json:"endpoint"`

	// TCPAddress is the TCP address of the remote proxy server, if applicable.
	//
	// Do not use if Endpoint is specified.
	TCPAddress conn.Addr `json:"tcpAddress"`

	// UDPAddress is the UDP address of the remote proxy server, if applicable.
	//
	// Do not use if Endpoint is specified.
	UDPAddress conn.Addr `json:"udpAddress"`

	DialerFwmark       int `json:"dialerFwmark"`
	DialerTrafficClass int `json:"dialerTrafficClass"`

	// TCP

	EnableTCP bool `json:"enableTCP"`
	DialerTFO bool `json:"dialerTFO"`

	// TCPFastOpenFallback enables runtime detection of TCP Fast Open support on the dialer.
	//
	// When enabled, the dialer will connect without TFO if TFO is not available on the system.
	// When disabled, the dialer will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	TCPFastOpenFallback bool `json:"tcpFastOpenFallback"`

	// MultipathTCP enables multipath TCP on the client.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	MultipathTCP bool `json:"multipathTCP"`

	// AllowSegmentedFixedLengthHeader disables the requirement that
	// the fixed-length header must be read in a single read call.
	//
	// This option is useful when the underlying stream transport
	// does not exhibit typical TCP behavior.
	//
	// Only applicable to Shadowsocks 2022 TCP.
	AllowSegmentedFixedLengthHeader bool `json:"allowSegmentedFixedLengthHeader"`

	// UDP

	EnableUDP bool `json:"enableUDP"`
	MTU       int  `json:"mtu"`

	// Socks5 is the protocol-specific configuration for "socks5".
	Socks5 Socks5ClientConfig `json:"socks5"`

	socks5AuthMsg []byte

	// HTTP is the protocol-specific configuration for "http".
	HTTP HTTPProxyClientConfig `json:"http"`

	// Shadowsocks

	PSK           []byte   `json:"psk"`
	IPSKs         [][]byte `json:"iPSKs"`
	PaddingPolicy string   `json:"paddingPolicy"`

	// SlidingWindowFilterSize is the size of the sliding window filter.
	//
	// The default value is 256.
	//
	// Only applicable to Shadowsocks 2022 UDP.
	SlidingWindowFilterSize int `json:"slidingWindowFilterSize"`

	cipherConfig *ss2022.ClientCipherConfig

	// Taint

	UnsafeRequestStreamPrefix  []byte `json:"unsafeRequestStreamPrefix"`
	UnsafeResponseStreamPrefix []byte `json:"unsafeResponseStreamPrefix"`

	tlsCertStore      *tlscerts.Store
	listenConfigCache conn.ListenConfigCache
	dialerCache       conn.DialerCache
	logger            *zap.Logger

	networkTCP string
	connDialer conn.Dialer
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

// TCPClient creates a zerocopy.TCPClient from the ClientConfig.
func (cc *ClientConfig) TCPClient() (zerocopy.TCPClient, error) {
	if !cc.EnableTCP {
		return nil, errNetworkDisabled
	}

	switch cc.Protocol {
	case "direct":
		return direct.NewTCPClient(cc.Name, cc.networkTCP, cc.connDialer), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneTCPClient(cc.Name, cc.networkTCP, cc.TCPAddress.String(), cc.connDialer), nil
	case "socks5":
		s5tcc := direct.Socks5TCPClientConfig{
			Name:    cc.Name,
			Network: cc.networkTCP,
			Address: cc.TCPAddress.String(),
			Dialer:  cc.connDialer,
			AuthMsg: cc.socks5AuthMsg,
		}
		return s5tcc.NewClient(), nil
	case "http":
		hpcc := httpproxy.ClientConfig{
			Name:                           cc.Name,
			Network:                        cc.networkTCP,
			Address:                        cc.TCPAddress.String(),
			Dialer:                         cc.connDialer,
			ServerName:                     cc.HTTP.ServerName,
			EncryptedClientHelloConfigList: cc.HTTP.ECHConfigList,
			Username:                       cc.HTTP.Username,
			Password:                       cc.HTTP.Password,
			UseTLS:                         cc.HTTP.UseTLS,
			UseBasicAuth:                   cc.HTTP.UseBasicAuth,
		}

		if cc.HTTP.CertList != "" {
			certs, getClientCert, ok := cc.tlsCertStore.GetClientCertList(cc.HTTP.CertList)
			if !ok {
				return nil, fmt.Errorf("certificate list not found: %q", cc.HTTP.CertList)
			}
			hpcc.Certificates = certs
			hpcc.GetClientCertificate = getClientCert
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
		return ss2022.NewTCPClient(cc.Name, cc.networkTCP, cc.TCPAddress.String(), cc.connDialer, cc.AllowSegmentedFixedLengthHeader, cc.cipherConfig, cc.UnsafeRequestStreamPrefix, cc.UnsafeResponseStreamPrefix), nil
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
		PathMTUDiscovery:  true,
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
		shouldPad, err := ss2022.ParsePaddingPolicy(cc.PaddingPolicy)
		if err != nil {
			return nil, err
		}

		switch {
		case cc.SlidingWindowFilterSize == 0:
			cc.SlidingWindowFilterSize = ss2022.DefaultSlidingWindowFilterSize
		case cc.SlidingWindowFilterSize < 0:
			return nil, fmt.Errorf("negative sliding window filter size: %d", cc.SlidingWindowFilterSize)
		}

		return ss2022.NewUDPClient(cc.Name, cc.Network, cc.UDPAddress, cc.MTU, listenConfig, uint64(cc.SlidingWindowFilterSize), cc.cipherConfig, shouldPad), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
}

// Socks5ClientConfig is the configuration for a SOCKS5 client.
type Socks5ClientConfig struct {
	// UserInfo is a username/password pair for authentication.
	socks5.UserInfo

	// EnableUserPassAuth controls whether to enable username/password authentication.
	EnableUserPassAuth bool `json:"enableUserPassAuth"`
}

// HTTPProxyClientConfig is the configuration for an HTTP proxy client.
type HTTPProxyClientConfig struct {
	// CertList is the name of the certificate list in the certificate store,
	// used as the client certificate for mutual TLS.
	// If empty, no client certificate is used.
	CertList string `json:"certList"`

	// RootCAs is the name of the X.509 certificate pool in the certificate store,
	// used for verifying the server certificate.
	// If empty, the system default is used.
	RootCAs string `json:"rootCAs"`

	// ServerName is the server name used for TLS.
	// If empty, it is inferred from the address.
	ServerName string `json:"serverName"`

	// ECHConfigList is a serialized ECHConfigList.
	// See [tls.Config.EncryptedClientHelloConfigList].
	ECHConfigList []byte `json:"echConfigList"`

	// Username is the username used for authentication.
	Username string `json:"username"`

	// Password is the password used for authentication.
	Password string `json:"password"`

	// UseTLS controls whether to use TLS.
	UseTLS bool `json:"useTLS"`

	// UseBasicAuth controls whether to use HTTP Basic Authentication.
	UseBasicAuth bool `json:"useBasicAuth"`
}

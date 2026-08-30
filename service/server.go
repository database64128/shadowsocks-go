package service

import (
	"errors"
	"fmt"
	"net/netip"
	"os/user"
	"strconv"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/httpproxy"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/ssnone"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ListenerConfig contains configuration options shared by all types of listeners.
type ListenerConfig struct {
	// Network specifies the address family of the listener.
	//
	//  - "tcp": TCP listener. Dual-stack on supported platforms. IPv4 on platforms without IPV6_V6ONLY.
	//  - "tcp4": IPv4 TCP listener.
	//  - "tcp6": IPv6-only TCP listener.
	//  - "udp": UDP listener. Dual-stack on supported platforms. IPv4 on platforms without IPV6_V6ONLY.
	//  - "udp4": IPv4 UDP listener.
	//  - "udp6": IPv6-only UDP listener.
	//  - "unix": SOCK_STREAM Unix domain socket listener.
	//  - "unixpacket": SOCK_SEQPACKET Unix domain socket listener.
	Network string `json:"network"`

	// Address is the address to listen on.
	Address string `json:"address"`
}

// IPListenerConfig contains configuration options shared by listeners that directly or indirectly utilize the IP stack.
type IPListenerConfig struct {
	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int `json:"fwmark,omitzero"`

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int `json:"trafficClass,omitzero"`

	// ReusePort enables SO_REUSEPORT on the listener.
	//
	// Available on Linux and the BSDs.
	ReusePort bool `json:"reusePort,omitzero"`

	// PathMTUDiscovery specifies the Path MTU Discovery mode on the listener.
	//
	// The default is [PMTUDModeAppDefault], which disables IP fragmentation for better performance and reliability.
	PathMTUDiscovery PMTUDMode `json:"pathMTUDiscovery,omitzero"`
}

// UnixDomainSocketPermissionsConfig configures the permissions of a Unix domain socket.
type UnixDomainSocketPermissionsConfig struct {
	// Owner optionally sets the owner of the Unix domain socket.
	// It can be an integer user ID or a string username.
	Owner jsoncfg.IntOrString `json:"owner,omitzero"`

	// Group optionally sets the group of the Unix domain socket.
	// It can be an integer group ID or a string group name.
	Group jsoncfg.IntOrString `json:"group,omitzero"`

	// Mode optionally sets the file mode of the Unix domain socket.
	// It must be an octal number in a string (e.g., "0660").
	Mode jsoncfg.FileMode `json:"mode,omitzero"`
}

// Build returns a [conn.UnixDomainSocketPermissions] from the configuration.
func (cfg *UnixDomainSocketPermissionsConfig) Build() (conn.UnixDomainSocketPermissions, error) {
	perms := conn.UnixDomainSocketPermissions{
		UID:  -1,
		GID:  -1,
		Mode: cfg.Mode.Value(),
	}

	if cfg.Owner.IsValid() || cfg.Group.IsValid() {
		switch cfg.Owner.Kind() {
		case jsoncfg.IntOrStringKindInt:
			perms.UID = cfg.Owner.Int()

		case jsoncfg.IntOrStringKindString:
			username := cfg.Owner.String()
			owner, err := user.Lookup(username)
			if err != nil {
				return conn.UnixDomainSocketPermissions{}, fmt.Errorf("failed to lookup user %q: %w", username, err)
			}

			perms.UID, err = strconv.Atoi(owner.Uid)
			if err != nil {
				return conn.UnixDomainSocketPermissions{}, fmt.Errorf("failed to parse UID for user %q: %w", username, err)
			}

		default:
			panic("unreachable")
		}

		switch cfg.Group.Kind() {
		case jsoncfg.IntOrStringKindInt:
			perms.GID = cfg.Group.Int()

		case jsoncfg.IntOrStringKindString:
			groupName := cfg.Group.String()
			group, err := user.LookupGroup(groupName)
			if err != nil {
				return conn.UnixDomainSocketPermissions{}, fmt.Errorf("failed to lookup group %q: %w", groupName, err)
			}

			perms.GID, err = strconv.Atoi(group.Gid)
			if err != nil {
				return conn.UnixDomainSocketPermissions{}, fmt.Errorf("failed to parse GID for group %q: %w", groupName, err)
			}

		default:
			panic("unreachable")
		}
	}

	return perms, nil
}

// InitialPayloadWaitConfig configures how a stream relay service handles the initial payload from an accepted connection.
type InitialPayloadWaitConfig struct {
	// DisableInitialPayloadWait disables the brief wait for initial payload.
	//
	// Setting it to true is useful when the listener only relays server-speaks-first protocols.
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait,omitzero"`

	// InitialPayloadWaitTimeout is the read timeout for the initial payload.
	//
	// The default value is 250ms.
	InitialPayloadWaitTimeout jsoncfg.Duration `json:"initialPayloadWaitTimeout,omitzero"`

	// InitialPayloadWaitBufferSize is the read buffer size for the initial payload.
	//
	// The default value is 1440.
	InitialPayloadWaitBufferSize int `json:"initialPayloadWaitBufferSize,omitzero"`
}

// Configure returns a stream relay initial payload wait configuration.
func (cfg InitialPayloadWaitConfig) Configure(serverNativeInitialPayload bool) (streamRelayInitialPayloadWaitConfig, error) {
	initialPayloadWaitTimeout := cfg.InitialPayloadWaitTimeout.Value()
	switch {
	case initialPayloadWaitTimeout == 0:
		initialPayloadWaitTimeout = defaultInitialPayloadWaitTimeout
	case initialPayloadWaitTimeout < 0:
		return streamRelayInitialPayloadWaitConfig{}, fmt.Errorf("negative initial payload wait timeout: %s", initialPayloadWaitTimeout)
	}

	initialPayloadWaitBufferSize := cfg.InitialPayloadWaitBufferSize
	switch {
	case initialPayloadWaitBufferSize == 0:
		initialPayloadWaitBufferSize = defaultInitialPayloadWaitBufferSize
	case initialPayloadWaitBufferSize < 0:
		return streamRelayInitialPayloadWaitConfig{}, fmt.Errorf("negative initial payload wait buffer size: %d", initialPayloadWaitBufferSize)
	}

	return streamRelayInitialPayloadWaitConfig{
		waitForInitialPayload:        !serverNativeInitialPayload && !cfg.DisableInitialPayloadWait,
		initialPayloadWaitTimeout:    initialPayloadWaitTimeout,
		initialPayloadWaitBufferSize: initialPayloadWaitBufferSize,
	}, nil
}

// TCPListenerConfig is the configuration for a TCP listener.
type TCPListenerConfig struct {
	ListenerConfig
	IPListenerConfig

	// FastOpen enables TCP Fast Open on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	FastOpen bool `json:"fastOpen,omitzero"`

	// FastOpenFallback enables runtime detection of TCP Fast Open support on the listener.
	//
	// When enabled, the listener will start without TFO if TFO is not available on the system.
	// When disabled, the listener will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	FastOpenFallback bool `json:"fastOpenFallback,omitzero"`

	// Multipath enables multipath TCP on the listener.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	Multipath bool `json:"multipath,omitzero"`

	// FastOpenBacklog specifies the maximum number of pending TFO connections on Linux.
	// If the value is 0, Go std's listen(2) backlog is used.
	//
	// On other platforms, a non-negative value is ignored, as they do not have the option to set the TFO backlog.
	//
	// On all platforms, a negative value disables TFO.
	FastOpenBacklog int `json:"fastOpenBacklog,omitzero"`

	// DeferAcceptSecs sets TCP_DEFER_ACCEPT to the given number of seconds on the listener.
	//
	// Available on Linux.
	DeferAcceptSecs int `json:"deferAcceptSecs,omitzero"`

	// UserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the listener.
	//
	// Available on Linux.
	UserTimeoutMsecs int `json:"userTimeoutMsecs,omitzero"`

	InitialPayloadWaitConfig
}

// Configure returns a TCP listener configuration.
func (lnc *TCPListenerConfig) Configure(listenConfigCache conn.TCPListenConfigCache, transparent, serverNativeInitialPayload bool) (streamRelayTCPListener, error) {
	switch lnc.Network {
	case "tcp", "tcp4", "tcp6":
	default:
		return streamRelayTCPListener{}, fmt.Errorf("invalid network: %q", lnc.Network)
	}

	ipwCfg, err := lnc.InitialPayloadWaitConfig.Configure(serverNativeInitialPayload)
	if err != nil {
		return streamRelayTCPListener{}, err
	}

	return streamRelayTCPListener{
		listenConfig: listenConfigCache.Get(conn.TCPListenSocketOptions{
			Fwmark:              lnc.Fwmark,
			TrafficClass:        lnc.TrafficClass,
			TCPFastOpenBacklog:  lnc.FastOpenBacklog,
			TCPDeferAcceptSecs:  lnc.DeferAcceptSecs,
			TCPUserTimeoutMsecs: lnc.UserTimeoutMsecs,
			ReusePort:           lnc.ReusePort,
			Transparent:         transparent,
			PathMTUDiscovery:    lnc.PathMTUDiscovery.TCP(),
			TCPFastOpen:         lnc.FastOpen,
			TCPFastOpenFallback: lnc.FastOpenFallback,
			MultipathTCP:        lnc.Multipath,
		}),
		network:                  lnc.Network,
		address:                  lnc.Address,
		initialPayloadWaitConfig: ipwCfg,
	}, nil
}

// UnixListenerConfig contains configuration options for a SOCK_STREAM or SOCK_SEQPACKET Unix domain socket listener.
type UnixListenerConfig struct {
	ListenerConfig
	UnixDomainSocketPermissionsConfig
	InitialPayloadWaitConfig
}

// Configure applies the configuration.
func (cfg *UnixListenerConfig) Configure(
	lnc *streamRelayUnixListener,
	socketConfigCache conn.UnixDomainSocketConfigCache,
	serverNativeInitialPayload bool,
) error {
	switch cfg.Network {
	case "unix", "unixpacket":
	default:
		return fmt.Errorf("invalid network: %q", cfg.Network)
	}

	perms, err := cfg.UnixDomainSocketPermissionsConfig.Build()
	if err != nil {
		return err
	}

	ipwCfg, err := cfg.InitialPayloadWaitConfig.Configure(serverNativeInitialPayload)
	if err != nil {
		return err
	}

	*lnc = streamRelayUnixListener{
		listenConfig:             socketConfigCache.Get(conn.UnixDomainSocketOptions{}),
		network:                  cfg.Network,
		address:                  cfg.Address,
		permissions:              perms,
		initialPayloadWaitConfig: ipwCfg,
	}

	return nil
}

// UDPListenerConfig is the configuration for a UDP server socket.
type UDPListenerConfig struct {
	ListenerConfig
	IPListenerConfig
	UDPPerfConfig

	// NATTimeout is the duration after which an inactive NAT mapping expires.
	//
	// The default value is 5 minutes.
	NATTimeout jsoncfg.Duration `json:"natTimeout,omitzero"`

	// AllowFragmentation controls whether to allow IP fragmentation.
	//
	// IP fragmentation does not reliably work over the Internet.
	// Sending fragmented packets will significantly reduce throughput.
	// Do not enable this option unless it is absolutely necessary.
	//
	// This field is obsolete and will be removed in a future release.
	// Setting it to true overrides PathMTUDiscovery to [PMTUDModeSystemDefault].
	AllowFragmentation bool `json:"allowFragmentation,omitzero"`
}

// Configure returns a UDP server socket configuration.
func (lnc *UDPListenerConfig) Configure(logger *zap.Logger, serverName string, socketConfigCache conn.UDPSocketConfigCache, minNATTimeout time.Duration, transparent bool) (udpRelayServerConn, error) {
	switch lnc.Network {
	case "udp", "udp4", "udp6":
	default:
		return udpRelayServerConn{}, fmt.Errorf("invalid network: %q", lnc.Network)
	}

	if err := lnc.UDPPerfConfig.CheckAndApplyDefaults(); err != nil {
		return udpRelayServerConn{}, err
	}

	pmtud := lnc.PathMTUDiscovery
	if lnc.AllowFragmentation {
		pmtud = PMTUDModeSystemDefault
		logger.Warn("allowFragmentation is obsolete and will be removed in a future release; migrate to pathMTUDiscovery for more granular control",
			zap.String("server", serverName),
		)
	}

	natTimeout := lnc.NATTimeout.Value()
	switch {
	case natTimeout == 0:
		natTimeout = defaultNatTimeout
	case natTimeout < minNATTimeout:
		return udpRelayServerConn{}, fmt.Errorf("NAT timeout %s is less than server's minimum NAT timeout %s", natTimeout, minNATTimeout)
	}

	return udpRelayServerConn{
		socketConfig: socketConfigCache.Get(conn.UDPSocketOptions{
			SendBufferSize:          conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:       conn.DefaultUDPSocketBufferSize,
			Fwmark:                  lnc.Fwmark,
			TrafficClass:            lnc.TrafficClass,
			ReusePort:               lnc.ReusePort,
			Transparent:             transparent,
			PathMTUDiscovery:        pmtud.UDP(),
			ReceivePacketInfo:       !transparent,
			ReceiveOriginalDestAddr: transparent,
		}),
		network:             lnc.Network,
		address:             lnc.Address,
		batchMode:           lnc.UDPPerfConfig.BatchMode,
		relayBatchSize:      lnc.UDPPerfConfig.RelayBatchSize,
		serverRecvBatchSize: lnc.UDPPerfConfig.ServerRecvBatchSize,
		sendChannelCapacity: lnc.UDPPerfConfig.SendChannelCapacity,
		natTimeout:          natTimeout,
	}, nil
}

// ServerConfig stores a server configuration.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	// Name is the name of the server.
	Name string `json:"name"`

	// Protocol is the protocol the server uses.
	//
	//  - "direct": Proxy all traffic to a fixed destination address specified by [TunnelRemoteAddress].
	//  - "tproxy": Transparent proxy. Only available on Linux, macOS, FreeBSD, and OpenBSD.
	//  - "socks5": SOCKS5 proxy.
	//  - "http": HTTP proxy.
	//  - "none", "plain": Shadowsocks "none" proxy.
	//  - "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm": Shadowsocks 2022 proxy.
	Protocol string `json:"protocol"`

	// TCPListeners is the list of TCP listeners.
	TCPListeners []TCPListenerConfig `json:"tcpListeners,omitzero"`

	// UDPListeners is the list of UDP listeners.
	UDPListeners []UDPListenerConfig `json:"udpListeners,omitzero"`

	// UnixListeners is the list of SOCK_STREAM and SOCK_SEQPACKET Unix domain socket listeners.
	UnixListeners []UnixListenerConfig `json:"unixListeners,omitzero"`

	// MTU is the MTU of the server's designated network path.
	// The value is used for calculating UDP receive buffer size.
	MTU int `json:"mtu,omitzero"`

	// Single listener configuration.

	Listen               string `json:"listen,omitzero"`
	ListenerFwmark       int    `json:"listenerFwmark,omitzero"`
	ListenerTrafficClass int    `json:"listenerTrafficClass,omitzero"`

	// TCP

	EnableTCP                 bool `json:"enableTCP,omitzero"`
	ListenerTFO               bool `json:"listenerTFO,omitzero"`
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait,omitzero"`

	// UDP

	EnableUDP     bool `json:"enableUDP,omitzero"`
	NatTimeoutSec int  `json:"natTimeoutSec,omitzero"`

	// UDP performance tuning

	UDPBatchMode           string `json:"udpBatchMode,omitzero"`
	UDPRelayBatchSize      int    `json:"udpRelayBatchSize,omitzero"`
	UDPServerRecvBatchSize int    `json:"udpServerRecvBatchSize,omitzero"`
	UDPSendChannelCapacity int    `json:"udpSendChannelCapacity,omitzero"`

	// TunnelRemoteAddress specifies the fixed destination address when [Protocol] is "direct".
	TunnelRemoteAddress conn.Addr `json:"tunnelRemoteAddress,omitzero"`

	// TunnelUDPTargetOnly controls whether to "connect" to the destination address for UDP.
	// If true, the server will drop packets that are not sent from [TunnelRemoteAddress].
	TunnelUDPTargetOnly bool `json:"tunnelUDPTargetOnly,omitzero"`

	tcpEnabled bool
	udpEnabled bool

	// AllowSegmentedFixedLengthHeader disables the requirement that
	// the fixed-length header must be read in a single read call.
	//
	// This option is useful when the underlying stream transport
	// does not exhibit typical TCP behavior.
	//
	// Only applicable to Shadowsocks 2022 TCP.
	AllowSegmentedFixedLengthHeader bool `json:"allowSegmentedFixedLengthHeader,omitzero"`

	// Socks5 is the protocol-specific configuration for "socks5".
	Socks5 Socks5ServerConfig `json:"socks5,omitzero"`

	// HTTP is the protocol-specific configuration for "http".
	HTTP HTTPProxyServerConfig `json:"http,omitzero"`

	// PSK specifies the pre-shared key (PSK) in single-user mode,
	// or the identity pre-shared key (iPSK) in multi-user mode for Shadowsocks 2022.
	PSK []byte `json:"psk,omitzero"`

	// UPSKStorePath specifies the path to the user pre-shared key (uPSK) store for Shadowsocks 2022.
	//
	// A non-empty value enables multi-user mode. Leave empty for single-user servers.
	UPSKStorePath string `json:"uPSKStorePath,omitzero"`

	// PaddingPolicy specifies the padding policy for Shadowsocks 2022 packets.
	//
	//  - "PadPlainDNS": Only add padding if the destination port is 53. (default)
	//  - "PadAll": Always add padding.
	//  - "NoPadding": Never add padding.
	PaddingPolicy ss2022.PaddingPolicyField `json:"paddingPolicy,omitzero"`

	// RejectPolicy specifies the reject policy for handling unauthenticated connections
	// to the Shadowsocks 2022 server.
	//
	//  - "JustClose": Close the connection without any special handling.
	//  - "ForceReset": Force a RST on the connection.
	//  - "CloseWriteDrain": Close the write end and drain the read end.
	//  - "ReplyWithGibberish": Keep reading and replying with random garbage until EOF or error.
	RejectPolicy ss2022.RejectPolicyField `json:"rejectPolicy,omitzero"`

	// SlidingWindowFilterSize is the size of the sliding window filter.
	//
	// The default value is 256.
	//
	// Only applicable to Shadowsocks 2022 UDP.
	SlidingWindowFilterSize uint64 `json:"slidingWindowFilterSize,omitzero"`

	userCipherConfig     ss2022.UserCipherConfig
	identityCipherConfig ss2022.ServerIdentityCipherConfig
	tcpCredStore         *ss2022.CredStore
	udpCredStore         *ss2022.CredStore

	// UnsafeFallbackAddress specifies the optional fallback destination address
	// for unauthenticated connections to the Shadowsocks 2022 server.
	UnsafeFallbackAddress conn.Addr `json:"unsafeFallbackAddress,omitzero"`

	// UnsafeRequestStreamPrefix specifies the prefix bytes expected at the beginning of
	// Shadowsocks 2022 request streams.
	//
	// The use of this feature "taints" the server.
	UnsafeRequestStreamPrefix []byte `json:"unsafeRequestStreamPrefix,omitzero"`

	// UnsafeResponseStreamPrefix specifies the prefix bytes expected at the beginning of
	// Shadowsocks 2022 response streams.
	//
	// The use of this feature "taints" the server.
	UnsafeResponseStreamPrefix []byte `json:"unsafeResponseStreamPrefix,omitzero"`

	tlsCertStore                *tlscerts.Store
	tcpListenConfigCache        conn.TCPListenConfigCache
	udpSocketConfigCache        conn.UDPSocketConfigCache
	unixDomainSocketConfigCache conn.UnixDomainSocketConfigCache
	collector                   stats.Collector
	router                      *router.Router
	logger                      *zap.Logger
	index                       int
}

// Initialize initializes the server configuration.
func (sc *ServerConfig) Initialize(tlsCertStore *tlscerts.Store, tcpListenConfigCache conn.TCPListenConfigCache, udpSocketConfigCache conn.UDPSocketConfigCache, unixDomainSocketConfigCache conn.UnixDomainSocketConfigCache, statsConfig stats.Config, router *router.Router, logger *zap.Logger, index int) error {
	sc.tcpEnabled = sc.EnableTCP || len(sc.TCPListeners) > 0 || len(sc.UnixListeners) > 0
	sc.udpEnabled = sc.EnableUDP || len(sc.UDPListeners) > 0

	switch sc.Protocol {
	case "direct":
		if !sc.TunnelRemoteAddress.IsValid() {
			return errors.New("tunnelRemoteAddress is required for simple tunnel")
		}

	case "http":
		if err := sc.HTTP.Validate(); err != nil {
			return err
		}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		err := ss2022.CheckPSKLength(sc.Protocol, sc.PSK, nil)
		if err != nil {
			return err
		}

		if sc.UPSKStorePath == "" {
			sc.userCipherConfig, err = ss2022.NewUserCipherConfig(sc.PSK, sc.udpEnabled)
			if err != nil {
				return err
			}
		} else {
			sc.identityCipherConfig, err = ss2022.NewServerIdentityCipherConfig(sc.PSK, sc.udpEnabled)
			if err != nil {
				return err
			}
		}
	}

	if sc.EnableTCP {
		sc.TCPListeners = append(sc.TCPListeners, TCPListenerConfig{
			Network:                   "tcp",
			Address:                   sc.Listen,
			Fwmark:                    sc.ListenerFwmark,
			TrafficClass:              sc.ListenerTrafficClass,
			FastOpen:                  sc.ListenerTFO,
			DisableInitialPayloadWait: sc.DisableInitialPayloadWait,
		})
	}

	if sc.EnableUDP {
		sc.UDPListeners = append(sc.UDPListeners, UDPListenerConfig{
			Network:             "udp",
			Address:             sc.Listen,
			Fwmark:              sc.ListenerFwmark,
			TrafficClass:        sc.ListenerTrafficClass,
			BatchMode:           sc.UDPBatchMode,
			RelayBatchSize:      sc.UDPRelayBatchSize,
			ServerRecvBatchSize: sc.UDPServerRecvBatchSize,
			SendChannelCapacity: sc.UDPSendChannelCapacity,
			NATTimeout:          jsoncfg.Duration(time.Duration(sc.NatTimeoutSec) * time.Second),
		})
	}

	if sc.EnableTCP || sc.EnableUDP {
		logger.Warn("Server-level single-listener fields are deprecated and will be removed in a future version. You can run with -fmtConf to migrate to the new format.",
			zap.String("server", sc.Name),
		)
	}

	sc.tlsCertStore = tlsCertStore
	sc.tcpListenConfigCache = tcpListenConfigCache
	sc.udpSocketConfigCache = udpSocketConfigCache
	sc.unixDomainSocketConfigCache = unixDomainSocketConfigCache
	sc.collector = statsConfig.Collector()
	sc.router = router
	sc.logger = logger
	sc.index = index
	return nil
}

// TCPRelay creates a TCP relay service from the ServerConfig.
func (sc *ServerConfig) TCPRelay() (*TCPRelay, error) {
	if len(sc.TCPListeners) == 0 && len(sc.UnixListeners) == 0 {
		return nil, errNetworkDisabled
	}

	var (
		server              netio.StreamServer
		err                 error
		listenerTransparent bool
	)

	switch sc.Protocol {
	case "direct":
		server = netio.NewStreamProxyServer(sc.TunnelRemoteAddress)

	case "tproxy":
		server, err = netio.NewTCPTransparentProxyServer()
		if err != nil {
			return nil, err
		}
		listenerTransparent = true

	case "redirect":
		server, err = netio.NewTCPRedirectServer()
		if err != nil {
			return nil, err
		}

	case "none", "plain":
		server = ssnone.StreamServer{}

	case "socks5":
		ssc := socks5.StreamServerConfig{
			Users:              sc.Socks5.Users,
			EnableUserPassAuth: sc.Socks5.EnableUserPassAuth,
			EnableTCP:          sc.tcpEnabled,
			EnableUDP:          sc.udpEnabled,
		}

		server, err = ssc.NewStreamServer()
		if err != nil {
			return nil, err
		}

	case "http":
		hpsc := httpproxy.ServerConfig{
			Users:                      sc.HTTP.Users,
			EncryptedClientHelloKeys:   sc.HTTP.EncryptedClientHelloKeys,
			EnableBasicAuth:            sc.HTTP.EnableBasicAuth,
			EnableTLS:                  sc.HTTP.EnableTLS,
			RequireAndVerifyClientCert: sc.HTTP.RequireAndVerifyClientCert,
		}

		if sc.HTTP.CertList != "" {
			certList, ok := sc.tlsCertStore.GetCertList(sc.HTTP.CertList)
			if !ok {
				return nil, fmt.Errorf("certificate list %q not found", sc.HTTP.CertList)
			}
			hpsc.Certificates, hpsc.GetCertificate = certList.GetCertificateFunc()
		}

		if sc.HTTP.ClientCAs != "" {
			pool, ok := sc.tlsCertStore.GetX509CertPool(sc.HTTP.ClientCAs)
			if !ok {
				return nil, fmt.Errorf("client CA X.509 certificate pool %q not found", sc.HTTP.ClientCAs)
			}
			hpsc.ClientCAs = pool
		}

		server, err = hpsc.NewProxyServer()
		if err != nil {
			return nil, err
		}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if sc.UnsafeFallbackAddress.IsValid() {
			sc.logger.Warn("Unsafe fallback taints the server", zap.String("server", sc.Name))
		}
		if len(sc.UnsafeRequestStreamPrefix) != 0 || len(sc.UnsafeResponseStreamPrefix) != 0 {
			sc.logger.Warn("Unsafe stream prefix taints the server", zap.String("server", sc.Name))
		}

		scc := ss2022.StreamServerConfig{
			AllowSegmentedFixedLengthHeader: sc.AllowSegmentedFixedLengthHeader,
			UserCipherConfig:                sc.userCipherConfig,
			IdentityCipherConfig:            sc.identityCipherConfig,
			RejectPolicy:                    sc.RejectPolicy.Policy(),
			UnsafeFallbackAddr:              sc.UnsafeFallbackAddress,
			UnsafeRequestStreamPrefix:       sc.UnsafeRequestStreamPrefix,
			UnsafeResponseStreamPrefix:      sc.UnsafeResponseStreamPrefix,
		}
		s := scc.NewStreamServer()
		sc.tcpCredStore = &s.CredStore
		server = s

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	serverInfo := server.StreamServerInfo()

	tcpListeners := make([]streamRelayTCPListener, len(sc.TCPListeners))
	for i := range tcpListeners {
		tcpListeners[i], err = sc.TCPListeners[i].Configure(sc.tcpListenConfigCache, listenerTransparent, serverInfo.NativeInitialPayload)
		if err != nil {
			return nil, err
		}
	}

	unixListeners := make([]streamRelayUnixListener, len(sc.UnixListeners))
	for i := range unixListeners {
		if err := sc.UnixListeners[i].Configure(&unixListeners[i], sc.unixDomainSocketConfigCache, serverInfo.NativeInitialPayload); err != nil {
			return nil, err
		}
	}

	return NewTCPRelay(sc.index, sc.Name, tcpListeners, unixListeners, server, sc.collector, sc.router, sc.logger), nil
}

// UDPRelay creates a UDP relay service from the ServerConfig.
func (sc *ServerConfig) UDPRelay(logger *zap.Logger, maxClientPackerHeadroom zerocopy.Headroom) (shadowsocks.Service, error) {
	if len(sc.UDPListeners) == 0 {
		return nil, errNetworkDisabled
	}

	if sc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	var (
		natServer                   zerocopy.UDPNATServer
		sessionServer               zerocopy.UDPSessionServer
		serverUnpackerHeadroom      zerocopy.Headroom
		transparentConnSocketConfig conn.UDPSocketConfig
		minNATTimeout               time.Duration
		err                         error
		listenerTransparent         bool
	)

	switch sc.Protocol {
	case "direct":
		natServer = direct.NewDirectUDPNATServer(sc.TunnelRemoteAddress, sc.TunnelUDPTargetOnly)

	case "tproxy":
		transparentConnSocketConfig = sc.udpSocketConfigCache.Get(conn.UDPSocketOptions{
			SendBufferSize:    conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize: conn.DefaultUDPSocketBufferSize,
			Fwmark:            sc.ListenerFwmark,
			TrafficClass:      sc.ListenerTrafficClass,
			Transparent:       true,
			ReusePort:         true,
			PathMTUDiscovery:  conn.PMTUDModeDo,
		})
		listenerTransparent = true

	case "none", "plain":
		natServer = direct.ShadowsocksNoneUDPNATServer{}

	case "socks5":
		natServer = direct.Socks5UDPNATServer{}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		s := ss2022.NewUDPServer(sc.SlidingWindowFilterSize, sc.userCipherConfig, sc.identityCipherConfig, sc.PaddingPolicy.Policy())
		sc.udpCredStore = &s.CredStore
		sessionServer = s

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	switch sc.Protocol {
	case "direct", "none", "plain", "socks5":
		serverUnpackerHeadroom = natServer.Info().UnpackerHeadroom
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		info := sessionServer.Info()
		serverUnpackerHeadroom = info.UnpackerHeadroom
		minNATTimeout = info.MinNATTimeout
	}

	packetBufHeadroom := zerocopy.UDPRelayHeadroom(maxClientPackerHeadroom, serverUnpackerHeadroom)
	packetBufRecvSize := zerocopy.MaxPacketSizeForAddr(sc.MTU, netip.IPv4Unspecified())
	packetBufSize := packetBufHeadroom.Front + packetBufRecvSize + packetBufHeadroom.Rear

	listeners := make([]udpRelayServerConn, len(sc.UDPListeners))

	for i := range listeners {
		listeners[i], err = sc.UDPListeners[i].Configure(logger, sc.Name, sc.udpSocketConfigCache, minNATTimeout, listenerTransparent)
		if err != nil {
			return nil, err
		}
	}

	switch sc.Protocol {
	case "direct", "none", "plain", "socks5":
		return NewUDPNATRelay(sc.Name, sc.index, sc.MTU, packetBufHeadroom.Front, packetBufRecvSize, packetBufSize, listeners, natServer, sc.collector, sc.router, sc.logger), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return NewUDPSessionRelay(sc.Name, sc.index, sc.MTU, packetBufHeadroom.Front, packetBufRecvSize, packetBufSize, listeners, sessionServer, sc.collector, sc.router, sc.logger), nil
	case "tproxy":
		return NewUDPTransparentRelay(sc.Name, sc.index, sc.MTU, packetBufHeadroom.Front, packetBufRecvSize, packetBufSize, listeners, transparentConnSocketConfig, sc.collector, sc.router, sc.logger)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}
}

// PostInit performs post-initialization tasks.
func (sc *ServerConfig) PostInit(credmgr *cred.Manager, serverByName map[string]ssm.Server, serverNames []string) error {
	var cms *cred.ManagedServer

	switch sc.Protocol {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if sc.UPSKStorePath != "" {
			var err error
			cms, err = credmgr.RegisterServer(sc.Name, sc.UPSKStorePath, len(sc.PSK), sc.tcpCredStore, sc.udpCredStore)
			if err != nil {
				return err
			}
		}
	}

	if serverByName != nil {
		serverByName[sc.Name] = ssm.Server{
			CredentialManager: cms,
			StatsCollector:    sc.collector,
		}
		serverNames[sc.index] = sc.Name
	}

	return nil
}

// Socks5ServerConfig is the configuration for a SOCKS5 server.
type Socks5ServerConfig struct {
	// Users is a list of users allowed to connect to the server.
	// It is ignored if none of the authentication methods are enabled.
	Users []socks5.UserInfo `json:"users,omitzero"`

	// EnableUserPassAuth controls whether to enable username/password authentication.
	//
	// CAVEAT: UDP listeners, if any, are not protected by username/password authentication.
	EnableUserPassAuth bool `json:"enableUserPassAuth,omitzero"`
}

// HTTPProxyServerConfig is the configuration for an HTTP proxy server.
type HTTPProxyServerConfig struct {
	// Users is a list of users allowed to connect to the server.
	// It is ignored if none of the authentication methods are enabled.
	Users []httpproxy.ServerUserCredentials `json:"users,omitzero"`

	// CertList is the name of the certificate list in the certificate store,
	// used as the server certificate for HTTPS.
	CertList string `json:"certList,omitzero"`

	// ClientCAs is the name of the X.509 certificate pool in the certificate store,
	// used as the root CA set for verifying client certificates.
	ClientCAs string `json:"clientCAs,omitzero"`

	// EncryptedClientHelloKeys are the ECH keys to use when a client attempts ECH.
	EncryptedClientHelloKeys []httpproxy.EncryptedClientHelloKey `json:"encryptedClientHelloKeys,omitzero"`

	// EnableBasicAuth controls whether to enable HTTP Basic Authentication.
	EnableBasicAuth bool `json:"enableBasicAuth,omitzero"`

	// EnableTLS controls whether to enable TLS.
	EnableTLS bool `json:"enableTLS,omitzero"`

	// RequireAndVerifyClientCert controls whether to require and verify client certificates.
	RequireAndVerifyClientCert bool `json:"requireAndVerifyClientCert,omitzero"`
}

// Validate validates the configuration.
func (c *HTTPProxyServerConfig) Validate() error {
	if c.EnableTLS && c.CertList == "" {
		return errors.New("certificate list is required for HTTPS")
	}
	return nil
}

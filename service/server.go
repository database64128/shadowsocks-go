package service

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/http"
	"github.com/database64128/shadowsocks-go/jsonhelper"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ListenerConfig is the shared part of TCP listener and UDP server socket configurations.
type ListenerConfig struct {
	// Network is the network type.
	// Valid values include "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6".
	Network string `json:"network"`

	// Address is the address to listen on.
	Address string `json:"address"`

	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int `json:"fwmark"`

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int `json:"trafficClass"`

	// ReusePort enables SO_REUSEPORT on the listener.
	//
	// Available on Linux and the BSDs.
	ReusePort bool `json:"reusePort"`
}

// TCPListenerConfig is the configuration for a TCP listener.
type TCPListenerConfig struct {
	// ListenerConfig is the shared part of TCP listener and UDP server socket configurations.
	ListenerConfig

	// FastOpen enables TCP Fast Open on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	FastOpen bool `json:"fastOpen"`

	// FastOpenFallback enables runtime detection of TCP Fast Open support on the listener.
	//
	// When enabled, the listener will start without TFO if TFO is not available on the system.
	// When disabled, the listener will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	FastOpenFallback bool `json:"fastOpenFallback"`

	// Multipath enables multipath TCP on the listener.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	Multipath bool `json:"multipath"`

	// DisableInitialPayloadWait disables the brief wait for initial payload.
	// Setting it to true is useful when the listener only relays server-speaks-first protocols.
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait"`

	// InitialPayloadWaitTimeout is the read timeout when waiting for the initial payload.
	//
	// The default value is 250ms.
	InitialPayloadWaitTimeout jsonhelper.Duration `json:"initialPayloadWaitTimeout"`

	// InitialPayloadWaitBufferSize is the read buffer size when waiting for the initial payload.
	//
	// The default value is 1440.
	InitialPayloadWaitBufferSize int `json:"initialPayloadWaitBufferSize"`

	// FastOpenBacklog specifies the maximum number of pending TFO connections on Linux.
	// If the value is 0, Go std's listen(2) backlog is used.
	//
	// On other platforms, a non-negative value is ignored, as they do not have the option to set the TFO backlog.
	//
	// On all platforms, a negative value disables TFO.
	FastOpenBacklog int `json:"fastOpenBacklog"`

	// DeferAcceptSecs sets TCP_DEFER_ACCEPT to the given number of seconds on the listener.
	//
	// Available on Linux.
	DeferAcceptSecs int `json:"deferAcceptSecs"`

	// UserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the listener.
	//
	// Available on Linux.
	UserTimeoutMsecs int `json:"userTimeoutMsecs"`
}

// Configure returns a TCP listener configuration.
func (lnc *TCPListenerConfig) Configure(listenConfigCache conn.ListenConfigCache, transparent, serverNativeInitialPayload bool) (tcpRelayListener, error) {
	switch lnc.Network {
	case "tcp", "tcp4", "tcp6":
	default:
		return tcpRelayListener{}, fmt.Errorf("invalid network: %s", lnc.Network)
	}

	initialPayloadWaitTimeout := lnc.InitialPayloadWaitTimeout.Value()

	switch {
	case initialPayloadWaitTimeout == 0:
		initialPayloadWaitTimeout = defaultInitialPayloadWaitTimeout
	case initialPayloadWaitTimeout < 0:
		return tcpRelayListener{}, fmt.Errorf("negative initial payload wait timeout: %s", initialPayloadWaitTimeout)
	}

	switch {
	case lnc.InitialPayloadWaitBufferSize == 0:
		lnc.InitialPayloadWaitBufferSize = defaultInitialPayloadWaitBufferSize
	case lnc.InitialPayloadWaitBufferSize < 0:
		return tcpRelayListener{}, fmt.Errorf("negative initial payload wait buffer size: %d", lnc.InitialPayloadWaitBufferSize)
	}

	return tcpRelayListener{
		listenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:              lnc.Fwmark,
			TrafficClass:        lnc.TrafficClass,
			TCPFastOpenBacklog:  lnc.FastOpenBacklog,
			TCPDeferAcceptSecs:  lnc.DeferAcceptSecs,
			TCPUserTimeoutMsecs: lnc.UserTimeoutMsecs,
			ReusePort:           lnc.ReusePort,
			Transparent:         transparent,
			TCPFastOpen:         lnc.FastOpen,
			TCPFastOpenFallback: lnc.FastOpenFallback,
			MultipathTCP:        lnc.Multipath,
		}),
		waitForInitialPayload:        !serverNativeInitialPayload && !lnc.DisableInitialPayloadWait,
		initialPayloadWaitTimeout:    initialPayloadWaitTimeout,
		initialPayloadWaitBufferSize: lnc.InitialPayloadWaitBufferSize,
		network:                      lnc.Network,
		address:                      lnc.Address,
	}, nil
}

// UDPListenerConfig is the configuration for a UDP server socket.
type UDPListenerConfig struct {
	// ListenerConfig is the shared part of TCP listener and UDP server socket configurations.
	ListenerConfig

	// UDPPerfConfig exposes performance tuning options.
	UDPPerfConfig

	// NATTimeout is the duration after which an inactive NAT mapping expires.
	//
	// The default value is 5 minutes.
	NATTimeout jsonhelper.Duration `json:"natTimeout"`
}

// Configure returns a UDP server socket configuration.
func (lnc *UDPListenerConfig) Configure(listenConfigCache conn.ListenConfigCache, minNATTimeout time.Duration, transparent bool) (udpRelayServerConn, error) {
	switch lnc.Network {
	case "udp", "udp4", "udp6":
	default:
		return udpRelayServerConn{}, fmt.Errorf("invalid network: %s", lnc.Network)
	}

	if err := lnc.UDPPerfConfig.CheckAndApplyDefaults(); err != nil {
		return udpRelayServerConn{}, err
	}

	natTimeout := lnc.NATTimeout.Value()

	switch {
	case natTimeout == 0:
		natTimeout = defaultNatTimeout
	case natTimeout < minNATTimeout:
		return udpRelayServerConn{}, fmt.Errorf("NAT timeout %s is less than server's minimum NAT timeout %s", natTimeout, minNATTimeout)
	}

	return udpRelayServerConn{
		listenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:            lnc.Fwmark,
			TrafficClass:      lnc.TrafficClass,
			ReusePort:         lnc.ReusePort,
			Transparent:       transparent,
			PathMTUDiscovery:  true,
			ReceivePacketInfo: true,
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
	// Valid values include "direct", "tproxy" (Linux only), "socks5", "http", "none", "plain", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm".
	Protocol string `json:"protocol"`

	// TCPListeners is the list of TCP listeners.
	TCPListeners []TCPListenerConfig `json:"tcpListeners"`

	// UDPListeners is the list of UDP listeners.
	UDPListeners []UDPListenerConfig `json:"udpListeners"`

	// MTU is the MTU of the server's designated network path.
	// The value is used for calculating UDP receive buffer size.
	MTU int `json:"mtu"`

	// Single listener configuration.

	Listen               string `json:"listen"`
	ListenerFwmark       int    `json:"listenerFwmark"`
	ListenerTrafficClass int    `json:"listenerTrafficClass"`

	// TCP

	EnableTCP                 bool `json:"enableTCP"`
	ListenerTFO               bool `json:"listenerTFO"`
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait"`

	// UDP

	EnableUDP     bool `json:"enableUDP"`
	NatTimeoutSec int  `json:"natTimeoutSec"`

	// UDP performance tuning

	UDPBatchMode           string `json:"udpBatchMode"`
	UDPRelayBatchSize      int    `json:"udpRelayBatchSize"`
	UDPServerRecvBatchSize int    `json:"udpServerRecvBatchSize"`
	UDPSendChannelCapacity int    `json:"udpSendChannelCapacity"`

	// Simple tunnel

	TunnelRemoteAddress conn.Addr `json:"tunnelRemoteAddress"`
	TunnelUDPTargetOnly bool      `json:"tunnelUDPTargetOnly"`

	tcpEnabled bool
	udpEnabled bool

	// AllowSegmentedFixedLengthHeader disables the requirement that
	// the fixed-length header must be read in a single read call.
	//
	// This option is useful when the underlying stream transport
	// does not exhibit typical TCP behavior.
	//
	// Only applicable to Shadowsocks 2022 TCP.
	AllowSegmentedFixedLengthHeader bool `json:"allowSegmentedFixedLengthHeader"`

	// Shadowsocks

	PSK           []byte `json:"psk"`
	UPSKStorePath string `json:"uPSKStorePath"`
	PaddingPolicy string `json:"paddingPolicy"`
	RejectPolicy  string `json:"rejectPolicy"`

	// SlidingWindowFilterSize is the size of the sliding window filter.
	//
	// The default value is 256.
	//
	// Only applicable to Shadowsocks 2022 UDP.
	SlidingWindowFilterSize int `json:"slidingWindowFilterSize"`

	userCipherConfig     ss2022.UserCipherConfig
	identityCipherConfig ss2022.ServerIdentityCipherConfig
	tcpCredStore         *ss2022.CredStore
	udpCredStore         *ss2022.CredStore

	// Taint

	UnsafeFallbackAddress      conn.Addr `json:"unsafeFallbackAddress"`
	UnsafeRequestStreamPrefix  []byte    `json:"unsafeRequestStreamPrefix"`
	UnsafeResponseStreamPrefix []byte    `json:"unsafeResponseStreamPrefix"`

	listenConfigCache conn.ListenConfigCache
	collector         stats.Collector
	router            *router.Router
	logger            *zap.Logger
	index             int
}

// Initialize initializes the server configuration.
func (sc *ServerConfig) Initialize(listenConfigCache conn.ListenConfigCache, collector stats.Collector, router *router.Router, logger *zap.Logger, index int) error {
	sc.tcpEnabled = sc.EnableTCP || len(sc.TCPListeners) > 0
	sc.udpEnabled = sc.EnableUDP || len(sc.UDPListeners) > 0

	switch sc.Protocol {
	case "direct":
		if !sc.TunnelRemoteAddress.IsValid() {
			return errors.New("tunnelRemoteAddress is required for simple tunnel")
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
			ListenerConfig: ListenerConfig{
				Network:      "tcp",
				Address:      sc.Listen,
				Fwmark:       sc.ListenerFwmark,
				TrafficClass: sc.ListenerTrafficClass,
			},
			FastOpen:                  sc.ListenerTFO,
			DisableInitialPayloadWait: sc.DisableInitialPayloadWait,
		})
	}

	if sc.EnableUDP {
		sc.UDPListeners = append(sc.UDPListeners, UDPListenerConfig{
			ListenerConfig: ListenerConfig{
				Network:      "udp",
				Address:      sc.Listen,
				Fwmark:       sc.ListenerFwmark,
				TrafficClass: sc.ListenerTrafficClass,
			},
			UDPPerfConfig: UDPPerfConfig{
				BatchMode:           sc.UDPBatchMode,
				RelayBatchSize:      sc.UDPRelayBatchSize,
				ServerRecvBatchSize: sc.UDPServerRecvBatchSize,
				SendChannelCapacity: sc.UDPSendChannelCapacity,
			},
			NATTimeout: jsonhelper.Duration(time.Duration(sc.NatTimeoutSec) * time.Second),
		})
	}

	sc.listenConfigCache = listenConfigCache
	sc.collector = collector
	sc.router = router
	sc.logger = logger
	sc.index = index
	return nil
}

// TCPRelay creates a TCP relay service from the ServerConfig.
func (sc *ServerConfig) TCPRelay() (*TCPRelay, error) {
	if len(sc.TCPListeners) == 0 {
		return nil, errNetworkDisabled
	}

	var (
		server              zerocopy.TCPServer
		connCloser          zerocopy.TCPConnCloser
		err                 error
		listenerTransparent bool
	)

	switch sc.Protocol {
	case "direct":
		server = direct.NewTCPServer(sc.TunnelRemoteAddress)

	case "tproxy":
		server, err = direct.NewTCPTransparentServer()
		if err != nil {
			return nil, err
		}
		listenerTransparent = true

	case "none", "plain":
		server = direct.NewShadowsocksNoneTCPServer()

	case "socks5":
		server = direct.NewSocks5TCPServer(sc.tcpEnabled, sc.udpEnabled)

	case "http":
		server = http.NewProxyServer(sc.logger)

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if len(sc.UnsafeRequestStreamPrefix) != 0 || len(sc.UnsafeResponseStreamPrefix) != 0 {
			sc.logger.Warn("Unsafe stream prefix taints the server", zap.String("server", sc.Name))
		}

		s := ss2022.NewTCPServer(sc.AllowSegmentedFixedLengthHeader, sc.userCipherConfig, sc.identityCipherConfig, sc.UnsafeRequestStreamPrefix, sc.UnsafeResponseStreamPrefix)
		sc.tcpCredStore = &s.CredStore
		server = s

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	serverInfo := server.Info()

	connCloser, err = zerocopy.ParseRejectPolicy(sc.RejectPolicy, serverInfo.DefaultTCPConnCloser)
	if err != nil {
		return nil, err
	}

	if sc.UnsafeFallbackAddress.IsValid() {
		sc.logger.Warn("Unsafe fallback taints the server",
			zap.String("server", sc.Name),
			zap.Stringer("fallbackAddress", sc.UnsafeFallbackAddress),
		)
	}

	listeners := make([]tcpRelayListener, len(sc.TCPListeners))

	for i := range listeners {
		listeners[i], err = sc.TCPListeners[i].Configure(sc.listenConfigCache, listenerTransparent, serverInfo.NativeInitialPayload)
		if err != nil {
			return nil, err
		}
	}

	return NewTCPRelay(sc.index, sc.Name, listeners, server, connCloser, sc.UnsafeFallbackAddress, sc.collector, sc.router, sc.logger), nil
}

// UDPRelay creates a UDP relay service from the ServerConfig.
func (sc *ServerConfig) UDPRelay(maxClientPackerHeadroom zerocopy.Headroom) (Relay, error) {
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
		transparentConnListenConfig conn.ListenConfig
		minNATTimeout               time.Duration
		err                         error
		listenerTransparent         bool
	)

	switch sc.Protocol {
	case "direct":
		natServer = direct.NewDirectUDPNATServer(sc.TunnelRemoteAddress, sc.TunnelUDPTargetOnly)

	case "tproxy":
		transparentConnListenConfig = sc.listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:           sc.ListenerFwmark,
			TrafficClass:     sc.ListenerTrafficClass,
			Transparent:      true,
			ReusePort:        true,
			PathMTUDiscovery: true,
		})
		listenerTransparent = true

	case "none", "plain":
		natServer = direct.ShadowsocksNoneUDPNATServer{}

	case "socks5":
		natServer = direct.Socks5UDPNATServer{}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		shouldPad, err := ss2022.ParsePaddingPolicy(sc.PaddingPolicy)
		if err != nil {
			return nil, err
		}

		switch {
		case sc.SlidingWindowFilterSize == 0:
			sc.SlidingWindowFilterSize = ss2022.DefaultSlidingWindowFilterSize
		case sc.SlidingWindowFilterSize < 0:
			return nil, fmt.Errorf("negative sliding window filter size: %d", sc.SlidingWindowFilterSize)
		}

		s := ss2022.NewUDPServer(uint64(sc.SlidingWindowFilterSize), sc.userCipherConfig, sc.identityCipherConfig, shouldPad)
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
		listeners[i], err = sc.UDPListeners[i].Configure(sc.listenConfigCache, minNATTimeout, listenerTransparent)
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
		return NewUDPTransparentRelay(sc.Name, sc.index, sc.MTU, packetBufHeadroom.Front, packetBufRecvSize, packetBufSize, listeners, transparentConnListenConfig, sc.collector, sc.router, sc.logger)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}
}

// PostInit performs post-initialization tasks.
func (sc *ServerConfig) PostInit(credman *cred.Manager, apiSM *ssm.ServerManager) error {
	var cms *cred.ManagedServer

	switch sc.Protocol {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if sc.UPSKStorePath != "" {
			var err error
			cms, err = credman.RegisterServer(sc.Name, sc.UPSKStorePath, len(sc.PSK), sc.tcpCredStore, sc.udpCredStore)
			if err != nil {
				return err
			}
		}
	}

	if apiSM != nil {
		apiSM.AddServer(sc.Name, cms, sc.collector)
	}

	return nil
}

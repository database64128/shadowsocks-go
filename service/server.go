package service

import (
	"fmt"
	"time"

	v1 "github.com/database64128/shadowsocks-go/api/v1"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/http"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ServerConfig stores a server configuration.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	Name                 string `json:"name"`
	Listen               string `json:"listen"`
	Protocol             string `json:"protocol"`
	ListenerFwmark       int    `json:"listenerFwmark"`
	ListenerTrafficClass int    `json:"listenerTrafficClass"`

	// TCP
	EnableTCP                 bool `json:"enableTCP"`
	ListenerTFO               bool `json:"listenerTFO"`
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait"`

	// UDP
	EnableUDP     bool `json:"enableUDP"`
	MTU           int  `json:"mtu"`
	NatTimeoutSec int  `json:"natTimeoutSec"`

	// UDP performance tuning
	UDPBatchMode           string `json:"udpBatchMode"`
	UDPRelayBatchSize      int    `json:"udpRelayBatchSize"`
	UDPServerRecvBatchSize int    `json:"udpServerRecvBatchSize"`
	UDPSendChannelCapacity int    `json:"udpSendChannelCapacity"`

	// Simple tunnel
	TunnelRemoteAddress conn.Addr `json:"tunnelRemoteAddress"`
	TunnelUDPTargetOnly bool      `json:"tunnelUDPTargetOnly"`

	// Shadowsocks
	PSK                  []byte `json:"psk"`
	UPSKStorePath        string `json:"uPSKStorePath"`
	PaddingPolicy        string `json:"paddingPolicy"`
	RejectPolicy         string `json:"rejectPolicy"`
	userCipherConfig     ss2022.UserCipherConfig
	identityCipherConfig ss2022.ServerIdentityCipherConfig
	tcpCredStore         *ss2022.CredStore
	udpCredStore         *ss2022.CredStore

	// Taint
	UnsafeFallbackAddress      *conn.Addr `json:"unsafeFallbackAddress"`
	UnsafeRequestStreamPrefix  []byte     `json:"unsafeRequestStreamPrefix"`
	UnsafeResponseStreamPrefix []byte     `json:"unsafeResponseStreamPrefix"`

	listenConfigCache conn.ListenConfigCache
	collector         stats.Collector
	router            *router.Router
	logger            *zap.Logger
	index             int
}

// Initialize initializes the server configuration.
func (sc *ServerConfig) Initialize(listenConfigCache conn.ListenConfigCache, collector stats.Collector, router *router.Router, logger *zap.Logger, index int) error {
	switch sc.Protocol {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		err := ss2022.CheckPSKLength(sc.Protocol, sc.PSK, nil)
		if err != nil {
			return err
		}

		if sc.UPSKStorePath == "" {
			sc.userCipherConfig, err = ss2022.NewUserCipherConfig(sc.PSK, sc.EnableUDP)
			if err != nil {
				return err
			}
		} else {
			sc.identityCipherConfig, err = ss2022.NewServerIdentityCipherConfig(sc.PSK, sc.EnableUDP)
			if err != nil {
				return err
			}
		}
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
	if !sc.EnableTCP && sc.Protocol != "socks5" {
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
		server = direct.NewSocks5TCPServer(sc.EnableTCP, sc.EnableUDP)

	case "http":
		server = http.NewProxyServer(sc.logger)

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if len(sc.UnsafeRequestStreamPrefix) != 0 || len(sc.UnsafeResponseStreamPrefix) != 0 {
			sc.logger.Warn("Unsafe stream prefix taints the server", zap.String("server", sc.Name))
		}

		s := ss2022.NewTCPServer(sc.userCipherConfig, sc.identityCipherConfig, sc.UnsafeRequestStreamPrefix, sc.UnsafeResponseStreamPrefix)
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

	if sc.UnsafeFallbackAddress != nil {
		sc.logger.Warn("Unsafe fallback taints the server",
			zap.String("server", sc.Name),
			zap.Stringer("fallbackAddress", sc.UnsafeFallbackAddress),
		)
	}

	waitForInitialPayload := !serverInfo.NativeInitialPayload && !sc.DisableInitialPayloadWait

	listenConfig := sc.listenConfigCache.Get(conn.ListenerSocketOptions{
		Fwmark:       sc.ListenerFwmark,
		TrafficClass: sc.ListenerTrafficClass,
		Transparent:  listenerTransparent,
		TCPFastOpen:  sc.ListenerTFO,
	})

	return NewTCPRelay(sc.index, sc.Name, sc.Listen, waitForInitialPayload, listenConfig, server, connCloser, sc.UnsafeFallbackAddress, sc.collector, sc.router, sc.logger), nil
}

// UDPRelay creates a UDP relay service from the ServerConfig.
func (sc *ServerConfig) UDPRelay(maxClientPackerHeadroom zerocopy.Headroom) (Relay, error) {
	if !sc.EnableUDP {
		return nil, errNetworkDisabled
	}

	if sc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	switch sc.UDPBatchMode {
	case "", "no", "sendmmsg":
	default:
		return nil, fmt.Errorf("unknown UDP batch mode: %s", sc.UDPBatchMode)
	}

	switch {
	case sc.UDPRelayBatchSize > 0 && sc.UDPRelayBatchSize <= 1024:
	case sc.UDPRelayBatchSize == 0:
		sc.UDPRelayBatchSize = defaultRelayBatchSize
	default:
		return nil, fmt.Errorf("UDP relay batch size out of range [0, 1024]: %d", sc.UDPRelayBatchSize)
	}

	switch {
	case sc.UDPServerRecvBatchSize > 0 && sc.UDPServerRecvBatchSize <= 1024:
	case sc.UDPServerRecvBatchSize == 0:
		sc.UDPServerRecvBatchSize = defaultServerRecvBatchSize
	default:
		return nil, fmt.Errorf("UDP server recv batch size out of range [0, 1024]: %d", sc.UDPServerRecvBatchSize)
	}

	switch {
	case sc.UDPSendChannelCapacity >= 64:
	case sc.UDPSendChannelCapacity == 0:
		sc.UDPSendChannelCapacity = defaultSendChannelCapacity
	default:
		return nil, fmt.Errorf("UDP send channel capacity must be at least 64: %d", sc.UDPSendChannelCapacity)
	}

	var (
		natTimeout                  time.Duration
		natServer                   zerocopy.UDPNATServer
		server                      zerocopy.UDPSessionServer
		serverConnListenConfig      conn.ListenConfig
		transparentConnListenConfig conn.ListenConfig
	)

	switch {
	case sc.NatTimeoutSec == 0:
		natTimeout = defaultNatTimeout
	case sc.NatTimeoutSec < minNatTimeoutSec:
		return nil, fmt.Errorf("natTimeoutSec too short: %d, must be at least %d", sc.NatTimeoutSec, minNatTimeoutSec)
	default:
		natTimeout = time.Duration(sc.NatTimeoutSec) * time.Second
	}

	switch sc.Protocol {
	case "direct":
		natServer = direct.NewDirectUDPNATServer(sc.TunnelRemoteAddress, sc.TunnelUDPTargetOnly)

	case "tproxy":

	case "none", "plain":
		natServer = direct.ShadowsocksNoneUDPNATServer{}

	case "socks5":
		natServer = direct.Socks5UDPNATServer{}

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		shouldPad, err := ss2022.ParsePaddingPolicy(sc.PaddingPolicy)
		if err != nil {
			return nil, err
		}

		s := ss2022.NewUDPServer(sc.userCipherConfig, sc.identityCipherConfig, shouldPad)
		sc.udpCredStore = &s.CredStore
		server = s

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	switch sc.Protocol {
	case "tproxy":
		serverConnListenConfig = sc.listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:                  sc.ListenerFwmark,
			TrafficClass:            sc.ListenerTrafficClass,
			Transparent:             true,
			PathMTUDiscovery:        true,
			ReceiveOriginalDestAddr: true,
		})
		transparentConnListenConfig = sc.listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:           sc.ListenerFwmark,
			TrafficClass:     sc.ListenerTrafficClass,
			Transparent:      true,
			ReusePort:        true,
			PathMTUDiscovery: true,
		})
	default:
		serverConnListenConfig = sc.listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:            sc.ListenerFwmark,
			TrafficClass:      sc.ListenerTrafficClass,
			PathMTUDiscovery:  true,
			ReceivePacketInfo: true,
		})
	}

	switch sc.Protocol {
	case "direct", "none", "plain", "socks5":
		return NewUDPNATRelay(sc.UDPBatchMode, sc.Name, sc.Listen, sc.UDPRelayBatchSize, sc.UDPServerRecvBatchSize, sc.UDPSendChannelCapacity, sc.index, sc.MTU, maxClientPackerHeadroom, natTimeout, natServer, serverConnListenConfig, sc.collector, sc.router, sc.logger), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return NewUDPSessionRelay(sc.UDPBatchMode, sc.Name, sc.Listen, sc.UDPRelayBatchSize, sc.UDPServerRecvBatchSize, sc.UDPSendChannelCapacity, sc.index, sc.MTU, maxClientPackerHeadroom, natTimeout, server, serverConnListenConfig, sc.collector, sc.router, sc.logger), nil
	case "tproxy":
		return NewUDPTransparentRelay(sc.Name, sc.Listen, sc.UDPRelayBatchSize, sc.UDPServerRecvBatchSize, sc.UDPSendChannelCapacity, sc.index, sc.MTU, maxClientPackerHeadroom, natTimeout, serverConnListenConfig, transparentConnListenConfig, sc.collector, sc.router, sc.logger)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}
}

// PostInit performs post-initialization tasks.
func (sc *ServerConfig) PostInit(credman *cred.Manager, apiSM *v1.ServerManager) error {
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

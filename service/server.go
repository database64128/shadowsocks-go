package service

import (
	"fmt"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/http"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ServerConfig stores a server configuration.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	Name           string `json:"name"`
	Listen         string `json:"listen"`
	Protocol       string `json:"protocol"`
	ListenerFwmark int    `json:"listenerFwmark"`

	// TCP
	EnableTCP                 bool `json:"enableTCP"`
	ListenerTFO               bool `json:"listenerTFO"`
	DisableInitialPayloadWait bool `json:"disableInitialPayloadWait"`

	// UDP
	EnableUDP     bool `json:"enableUDP"`
	MTU           int  `json:"mtu"`
	NatTimeoutSec int  `json:"natTimeoutSec"`

	// Simple tunnel
	TunnelRemoteAddress conn.Addr `json:"tunnelRemoteAddress"`
	TunnelUDPTargetOnly bool      `json:"tunnelUDPTargetOnly"`

	// Shadowsocks
	PSK           []byte   `json:"psk"`
	UPSKs         [][]byte `json:"uPSKs"`
	PaddingPolicy string   `json:"paddingPolicy"`
	RejectPolicy  string   `json:"rejectPolicy"`
	cipherConfig  *ss2022.CipherConfig
	uPSKMap       map[[ss2022.IdentityHeaderLength]byte]*ss2022.CipherConfig
}

// TCPRelay creates a TCP relay service from the ServerConfig.
func (sc *ServerConfig) TCPRelay(router *router.Router, logger *zap.Logger) (*TCPRelay, error) {
	if !sc.EnableTCP && sc.Protocol != "socks5" {
		return nil, errNetworkDisabled
	}

	var (
		server     zerocopy.TCPServer
		connCloser zerocopy.TCPConnCloser
		err        error
	)

	switch sc.Protocol {
	case "direct":
		server = direct.NewTCPServer(sc.TunnelRemoteAddress)

	case "none", "plain":
		server = direct.NewShadowsocksNoneTCPServer()

	case "socks5":
		server = direct.NewSocks5TCPServer(sc.EnableTCP, sc.EnableUDP)

	case "http":
		server = http.NewProxyServer(logger)

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if sc.cipherConfig == nil {
			sc.cipherConfig, err = ss2022.NewCipherConfig(sc.Protocol, sc.PSK, sc.UPSKs)
			if err != nil {
				return nil, err
			}
			sc.uPSKMap = sc.cipherConfig.ServerPSKHashMap()
		}

		server = ss2022.NewTCPServer(sc.cipherConfig, sc.uPSKMap)

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	connCloser, err = zerocopy.ParseRejectPolicy(sc.RejectPolicy, server)
	if err != nil {
		return nil, err
	}

	waitForInitialPayload := !server.NativeInitialPayload() && !sc.DisableInitialPayloadWait

	return NewTCPRelay(sc.Name, sc.Listen, sc.ListenerFwmark, sc.ListenerTFO, waitForInitialPayload, server, connCloser, router, logger), nil
}

// UDPRelay creates a UDP relay service from the ServerConfig.
func (sc *ServerConfig) UDPRelay(router *router.Router, logger *zap.Logger, preferIPv6 bool, batchMode string, batchSize, maxClientFrontHeadroom, maxClientRearHeadroom int) (Relay, error) {
	if !sc.EnableUDP {
		return nil, errNetworkDisabled
	}

	if sc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	var (
		natTimeout time.Duration
		natServer  zerocopy.UDPNATServer
		server     zerocopy.UDPSessionServer
		err        error
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

	case "none", "plain":
		natServer = direct.DefaultShadowsocksNoneUDPNATServer

	case "socks5":
		natServer = direct.DefaultSocks5UDPNATServer

	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if sc.cipherConfig == nil {
			sc.cipherConfig, err = ss2022.NewCipherConfig(sc.Protocol, sc.PSK, sc.UPSKs)
			if err != nil {
				return nil, err
			}
			sc.uPSKMap = sc.cipherConfig.ServerPSKHashMap()
		}

		shouldPad, err := ss2022.ParsePaddingPolicy(sc.PaddingPolicy)
		if err != nil {
			return nil, err
		}

		server = ss2022.NewUDPServer(sc.cipherConfig, shouldPad, sc.uPSKMap)

	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}

	switch sc.Protocol {
	case "direct", "none", "plain", "socks5":
		return NewUDPNATRelay(batchMode, sc.Name, sc.Listen, batchSize, sc.ListenerFwmark, sc.MTU, maxClientFrontHeadroom, maxClientRearHeadroom, preferIPv6, natTimeout, natServer, router, logger), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return NewUDPSessionRelay(batchMode, sc.Name, sc.Listen, batchSize, sc.ListenerFwmark, sc.MTU, maxClientFrontHeadroom, maxClientRearHeadroom, preferIPv6, natTimeout, server, router, logger), nil
	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}
}

package service

import (
	"fmt"

	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/http"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/socks5"
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
	EnableUDP bool `json:"enableUDP"`
	MTU       int  `json:"mtu"`

	// Simple tunnel
	TunnelRemoteAddress string `json:"tunnelRemoteAddress"`
	tunnelRemoteAddr    socks5.Addr

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
		if sc.tunnelRemoteAddr == nil {
			sc.tunnelRemoteAddr, err = socks5.ParseAddr(sc.TunnelRemoteAddress)
			if err != nil {
				return nil, err
			}
		}
		server = direct.NewTCPServer(sc.tunnelRemoteAddr)

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
		server             zerocopy.UDPServer
		serverPackUnpacker zerocopy.PackUnpacker
		err                error
	)

	switch sc.Protocol {
	case "direct":
		if sc.tunnelRemoteAddr == nil {
			sc.tunnelRemoteAddr, err = socks5.ParseAddr(sc.TunnelRemoteAddress)
			if err != nil {
				return nil, err
			}
		}
		serverPackUnpacker = direct.NewDirectServer(sc.tunnelRemoteAddr)

	case "none", "plain":
		serverPackUnpacker = &direct.DefaultShadowsocksNonePacketPackUnpacker

	case "socks5":
		serverPackUnpacker = &direct.DefaultSocks5PacketPackUnpacker

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
		return NewUDPNATRelay(batchMode, sc.Name, sc.Listen, batchSize, sc.ListenerFwmark, sc.MTU, maxClientFrontHeadroom, maxClientRearHeadroom, preferIPv6, serverPackUnpacker, serverPackUnpacker, router, logger), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return NewUDPSessionRelay(batchMode, sc.Name, sc.Listen, batchSize, sc.ListenerFwmark, sc.MTU, maxClientFrontHeadroom, maxClientRearHeadroom, preferIPv6, server, router, logger), nil
	default:
		return nil, fmt.Errorf("invalid protocol: %s", sc.Protocol)
	}
}

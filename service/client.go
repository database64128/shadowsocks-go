package service

import (
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/http"
	"github.com/database64128/shadowsocks-go/ss2022"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ClientConfig stores a client configuration.
// It may be marshaled as or unmarshaled from JSON.
type ClientConfig struct {
	Name         string    `json:"name"`
	Endpoint     conn.Addr `json:"endpoint"`
	Protocol     string    `json:"protocol"`
	DialerFwmark int       `json:"dialerFwmark"`

	// TCP
	EnableTCP bool `json:"enableTCP"`
	DialerTFO bool `json:"dialerTFO"`

	// UDP
	EnableUDP bool `json:"enableUDP"`
	MTU       int  `json:"mtu"`

	// Shadowsocks
	PSK           []byte   `json:"psk"`
	IPSKs         [][]byte `json:"iPSKs"`
	PaddingPolicy string   `json:"paddingPolicy"`
	cipherConfig  *ss2022.CipherConfig
	eihPSKHashes  [][ss2022.IdentityHeaderLength]byte
}

// TCPClient creates a zerocopy.TCPClient from the ClientConfig.
func (cc *ClientConfig) TCPClient(logger *zap.Logger) (zerocopy.TCPClient, error) {
	if !cc.EnableTCP {
		return nil, errNetworkDisabled
	}

	switch cc.Protocol {
	case "direct":
		return direct.NewTCPClient(cc.DialerTFO, cc.DialerFwmark), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneTCPClient(cc.Endpoint.String(), cc.DialerTFO, cc.DialerFwmark), nil
	case "socks5":
		return direct.NewSocks5TCPClient(cc.Endpoint.String(), cc.DialerTFO, cc.DialerFwmark), nil
	case "http":
		return http.NewProxyClient(cc.Endpoint.String(), cc.DialerTFO, cc.DialerFwmark), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if cc.cipherConfig == nil {
			var err error
			cc.cipherConfig, err = ss2022.NewCipherConfig(cc.Protocol, cc.PSK, cc.IPSKs)
			if err != nil {
				return nil, err
			}
			cc.eihPSKHashes = cc.cipherConfig.ClientPSKHashes()
		}
		return ss2022.NewTCPClient(cc.Endpoint.String(), cc.DialerTFO, cc.DialerFwmark, cc.cipherConfig, cc.eihPSKHashes), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
}

func (cc *ClientConfig) UDPClient(logger *zap.Logger, preferIPv6 bool) (zerocopy.UDPClient, error) {
	if !cc.EnableUDP {
		return nil, errNetworkDisabled
	}

	if cc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	var (
		endpointAddrPort netip.AddrPort
		err              error
	)

	// Resolve endpoint address for some protocols.
	switch cc.Protocol {
	case "none", "plain", "socks5", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		endpointAddrPort, err = cc.Endpoint.ResolveIPPort(preferIPv6)
		if err != nil {
			return nil, err
		}

		// Map to v6 since natConn is v6 socket.
		endpointAddrPort = conn.AddrPortv4Mappedv6(endpointAddrPort)
	}

	switch cc.Protocol {
	case "direct":
		return direct.NewUDPClient(cc.MTU, cc.DialerFwmark, preferIPv6), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneUDPClient(endpointAddrPort, cc.MTU, cc.DialerFwmark), nil
	case "socks5":
		return direct.NewSocks5UDPClient(endpointAddrPort, cc.MTU, cc.DialerFwmark), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if cc.cipherConfig == nil {
			cc.cipherConfig, err = ss2022.NewCipherConfig(cc.Protocol, cc.PSK, cc.IPSKs)
			if err != nil {
				return nil, err
			}
			cc.eihPSKHashes = cc.cipherConfig.ClientPSKHashes()
		}

		shouldPad, err := ss2022.ParsePaddingPolicy(cc.PaddingPolicy)
		if err != nil {
			return nil, err
		}

		return ss2022.NewUDPClient(endpointAddrPort, cc.MTU, cc.DialerFwmark, cc.cipherConfig, shouldPad, cc.eihPSKHashes), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
}

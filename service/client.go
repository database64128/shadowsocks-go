package service

import (
	"errors"
	"fmt"

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
	// Name is the name of the client.
	Name string `json:"name"`

	// Protocol is the protocol used by the client.
	// Valid values include "direct", "socks5", "http", "none", "plain", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm".
	Protocol string `json:"protocol"`

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

	// Shadowsocks

	PSK           []byte   `json:"psk"`
	IPSKs         [][]byte `json:"iPSKs"`
	PaddingPolicy string   `json:"paddingPolicy"`
	cipherConfig  *ss2022.ClientCipherConfig

	// Taint

	UnsafeRequestStreamPrefix  []byte `json:"unsafeRequestStreamPrefix"`
	UnsafeResponseStreamPrefix []byte `json:"unsafeResponseStreamPrefix"`

	listenConfigCache conn.ListenConfigCache
	dialerCache       conn.DialerCache
	logger            *zap.Logger
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
func (cc *ClientConfig) Initialize(listenConfigCache conn.ListenConfigCache, dialerCache conn.DialerCache, logger *zap.Logger) (err error) {
	if err = cc.checkAddresses(); err != nil {
		return
	}

	switch cc.Protocol {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if err = ss2022.CheckPSKLength(cc.Protocol, cc.PSK, cc.IPSKs); err != nil {
			return
		}
		cc.cipherConfig, err = ss2022.NewClientCipherConfig(cc.PSK, cc.IPSKs, cc.EnableUDP)
		if err != nil {
			return
		}
	}

	cc.listenConfigCache = listenConfigCache
	cc.dialerCache = dialerCache
	cc.logger = logger
	return
}

// TCPClient creates a zerocopy.TCPClient from the ClientConfig.
func (cc *ClientConfig) TCPClient() (zerocopy.TCPClient, error) {
	if !cc.EnableTCP {
		return nil, errNetworkDisabled
	}

	dialer := cc.dialerCache.Get(conn.DialerSocketOptions{
		Fwmark:       cc.DialerFwmark,
		TrafficClass: cc.DialerTrafficClass,
		TCPFastOpen:  cc.DialerTFO,
	})

	switch cc.Protocol {
	case "direct":
		return direct.NewTCPClient(cc.Name, dialer), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneTCPClient(cc.Name, cc.TCPAddress.String(), dialer), nil
	case "socks5":
		return direct.NewSocks5TCPClient(cc.Name, cc.TCPAddress.String(), dialer), nil
	case "http":
		return http.NewProxyClient(cc.Name, cc.TCPAddress.String(), dialer), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		if len(cc.UnsafeRequestStreamPrefix) != 0 || len(cc.UnsafeResponseStreamPrefix) != 0 {
			cc.logger.Warn("Unsafe stream prefix taints the client", zap.String("client", cc.Name))
		}
		return ss2022.NewTCPClient(cc.Name, cc.TCPAddress.String(), dialer, cc.AllowSegmentedFixedLengthHeader, cc.cipherConfig, cc.UnsafeRequestStreamPrefix, cc.UnsafeResponseStreamPrefix), nil
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
		Fwmark:           cc.DialerFwmark,
		TrafficClass:     cc.DialerTrafficClass,
		PathMTUDiscovery: true,
	})

	switch cc.Protocol {
	case "direct":
		return direct.NewDirectUDPClient(cc.Name, cc.MTU, listenConfig), nil
	case "none", "plain":
		return direct.NewShadowsocksNoneUDPClient(cc.UDPAddress, cc.Name, cc.MTU, listenConfig), nil
	case "socks5":
		dialer := cc.dialerCache.Get(conn.DialerSocketOptions{
			Fwmark:       cc.DialerFwmark,
			TrafficClass: cc.DialerTrafficClass,
			TCPFastOpen:  cc.DialerTFO,
		})
		return direct.NewSocks5UDPClient(cc.logger, cc.Name, cc.UDPAddress.String(), dialer, cc.MTU, listenConfig), nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		shouldPad, err := ss2022.ParsePaddingPolicy(cc.PaddingPolicy)
		if err != nil {
			return nil, err
		}
		return ss2022.NewUDPClient(cc.UDPAddress, cc.Name, cc.MTU, listenConfig, cc.cipherConfig, shouldPad), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", cc.Protocol)
	}
}

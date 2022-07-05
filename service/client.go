package service

import (
	"go.uber.org/zap"
)

// ClientConfig stores configurations for a client service.
// It may be marshaled as or unmarshaled from JSON.
type ClientConfig struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	Protocol     string `json:"protocol"`
	DialerFwmark int    `json:"dialerFwmark"`

	// TCP
	EnableTCP bool `json:"enableTCP"`
	DialerTFO bool `json:"dialerTFO"`

	// UDP
	EnableUDP bool `json:"enableUDP"`
	MTU       int  `json:"mtu"`

	// Simple tunnel
	TunnelRemoteAddress string `json:"tunnelRemoteAddress"`

	// Shadowsocks
	PSK   []byte   `json:"psk"`
	IPSKs [][]byte `json:"iPSKs"`
}

// NewClientService creates a client service from the specified client config.
// Call the Start method on the returned service to start it.
func NewClientService(config ClientConfig, logger *zap.Logger) Relay {
	return nil
}

package service

import "go.uber.org/zap"

// ServerConfig stores configurations for a server service.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	Name           string `json:"name"`
	Listen         string `json:"listen"`
	Protocol       string `json:"protocol"`
	ListenerFwmark int    `json:"listenerFwmark"`

	// TCP
	EnableTCP   bool `json:"enableTCP"`
	ListenerTFO bool `json:"listenerTFO"`

	// UDP
	EnableUDP       bool `json:"enableUDP"`
	DisableSendmmsg bool `json:"disableSendmmsg"`
	MTU             int  `json:"mtu"`

	// Shadowsocks
	PSK   []byte   `json:"psk"`
	UPSKs [][]byte `json:"uPSKs"`
}

// NewServerService creates a server service from the specified server config.
// Call the Start method on the returned service to start it.
func NewServerService(config ServerConfig, logger *zap.Logger) Service {
	return nil
}

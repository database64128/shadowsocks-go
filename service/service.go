package service

import (
	"errors"
	"fmt"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/router"
	"go.uber.org/zap"
)

// Relay is a relay service that accepts incoming connections/sessions on a server
// and dispatches them to a client selected by the router.
//
// Both TCPRelay and UDPRelay implement this interface.
type Relay interface {
	// String returns the relay service's name.
	// This method may be called on a nil pointer.
	String() string

	// Start starts the relay service.
	Start() error

	// Stop stops the relay service.
	Stop() error
}

// ServiceConfig stores configurations for client and server services.
// It may be marshaled as or unmarshaled from JSON.
// Call the Start method to start all configured services.
// Call the Stop method to properly close all running services.
type ServiceConfig struct {
	Servers      []ServerConfig        `json:"servers"`
	Clients      []ClientConfig        `json:"clients"`
	DNS          []dns.ResolverConfig  `json:"dns"`
	Router       []router.RouterConfig `json:"router"`
	UDPBatchMode string                `json:"udpBatchMode"`

	services []Relay
	//router   Router
	logger *zap.Logger
}

// Start starts all configured server (interface) and client (peer) services.
func (sc *ServiceConfig) Start(logger *zap.Logger) error {
	sc.logger = logger

	// Initialization order: clients -> DNS -> router -> servers
	serverCount := len(sc.Servers)
	clientCount := len(sc.Clients)
	serviceCount := serverCount + clientCount
	if serviceCount == 0 {
		return errors.New("no services to start")
	}

	sc.services = make([]Relay, serviceCount)

	for i := range sc.Servers {
		s := NewServerService(sc.Servers[i], logger)
		sc.services[i] = s

		err := s.Start()
		if err != nil {
			return fmt.Errorf("failed to start %s: %w", s.String(), err)
		}
	}

	for i := range sc.Clients {
		c := NewClientService(sc.Clients[i], logger)
		sc.services[serverCount+i] = c

		err := c.Start()
		if err != nil {
			return fmt.Errorf("failed to start %s: %w", c.String(), err)
		}
	}

	return nil
}

// Stop stops all running services.
func (sc *ServiceConfig) Stop() {
	for _, s := range sc.services {
		err := s.Stop()
		if err != nil {
			sc.logger.Warn("An error occurred while stopping service",
				zap.Stringer("service", s),
				zap.NamedError("stopError", err),
			)
		}
		sc.logger.Info("Stopped service", zap.Stringer("service", s))
	}
}

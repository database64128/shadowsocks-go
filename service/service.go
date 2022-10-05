package service

import (
	"errors"
	"fmt"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

var errNetworkDisabled = errors.New("this network (tcp or udp) is disabled")

// Relay is a relay service that accepts incoming connections/sessions on a server
// and dispatches them to a client selected by the router.
//
// Both TCPRelay and UDPRelay implement this interface.
type Relay interface {
	// String returns the relay service's name.
	String() string

	// Start starts the relay service.
	Start() error

	// Stop stops the relay service.
	Stop() error
}

// Config is the main configuration structure.
// It may be marshaled as or unmarshaled from JSON.
// Call the Start method to start all configured services.
// Call the Stop method to properly close all running services.
type Config struct {
	Servers       []ServerConfig       `json:"servers"`
	Clients       []ClientConfig       `json:"clients"`
	DNS           []dns.ResolverConfig `json:"dns"`
	Router        router.Config        `json:"router"`
	UDPBatchMode  string               `json:"udpBatchMode"`
	UDPBatchSize  int                  `json:"udpBatchSize"`
	UDPPreferIPv6 bool                 `json:"udpPreferIPv6"`

	services []Relay
	router   *router.Router
	logger   *zap.Logger
}

// Start starts all configured services.
//
// Initialization order: clients -> DNS -> router -> servers
func (sc *Config) Start(logger *zap.Logger) error {
	if len(sc.Servers) == 0 {
		return errors.New("no services to start")
	}

	if len(sc.Clients) == 0 {
		sc.Clients = []ClientConfig{
			{
				Name:      "direct",
				Protocol:  "direct",
				EnableTCP: true,
				DialerTFO: true,
				EnableUDP: true,
				MTU:       1500,
			},
		}
	}

	switch sc.UDPBatchMode {
	case "", "no", "sendmmsg":
	default:
		return fmt.Errorf("unknown UDP batch mode: %s", sc.UDPBatchMode)
	}

	switch {
	case sc.UDPBatchSize > 0 && sc.UDPBatchSize <= 1024:
	case sc.UDPBatchSize == 0:
		sc.UDPBatchSize = defaultRecvmmsgMsgvecSize
	default:
		return fmt.Errorf("UDP batch size out of range [0, 1024]: %d", sc.UDPBatchSize)
	}

	sc.logger = logger

	tcpClientMap := make(map[string]zerocopy.TCPClient, len(sc.Clients))
	udpClientMap := make(map[string]zerocopy.UDPClient, len(sc.Clients))
	var maxClientFrontHeadroom, maxClientRearHeadroom int

	for _, clientConfig := range sc.Clients {
		tcpClient, err := clientConfig.TCPClient(logger)
		switch err {
		case errNetworkDisabled:
		case nil:
			tcpClientMap[clientConfig.Name] = tcpClient
		default:
			return fmt.Errorf("failed to create TCP client for %s: %w", clientConfig.Name, err)
		}

		udpClient, err := clientConfig.UDPClient(logger, sc.UDPPreferIPv6)
		switch err {
		case errNetworkDisabled:
		case nil:
			udpClientMap[clientConfig.Name] = udpClient
			frontHeadroom := udpClient.FrontHeadroom()
			if frontHeadroom > maxClientFrontHeadroom {
				maxClientFrontHeadroom = frontHeadroom
			}
			rearHeadroom := udpClient.RearHeadroom()
			if rearHeadroom > maxClientRearHeadroom {
				maxClientRearHeadroom = rearHeadroom
			}
		default:
			return fmt.Errorf("failed to create UDP client for %s: %w", clientConfig.Name, err)
		}
	}

	resolvers := make([]*dns.Resolver, len(sc.DNS))
	resolverMap := make(map[string]*dns.Resolver, len(sc.DNS))

	for i, resolverConfig := range sc.DNS {
		resolver, err := resolverConfig.Resolver(tcpClientMap, udpClientMap, logger)
		if err != nil {
			return fmt.Errorf("failed to create DNS resolver %s: %w", resolverConfig.Name, err)
		}

		resolvers[i] = resolver
		resolverMap[resolverConfig.Name] = resolver
	}

	var err error
	sc.router, err = sc.Router.Router(logger, resolvers, resolverMap, tcpClientMap, udpClientMap)
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	sc.services = make([]Relay, 0, 2*len(sc.Servers))

	for _, serverConfig := range sc.Servers {
		tcpRelay, err := serverConfig.TCPRelay(sc.router, logger)
		switch err {
		case errNetworkDisabled:
		case nil:
			sc.services = append(sc.services, tcpRelay)
		default:
			return fmt.Errorf("failed to create TCP relay service for %s: %w", serverConfig.Name, err)
		}

		udpRelay, err := serverConfig.UDPRelay(sc.router, logger, sc.UDPBatchMode, sc.UDPBatchSize, maxClientFrontHeadroom, maxClientRearHeadroom)
		switch err {
		case errNetworkDisabled:
		case nil:
			sc.services = append(sc.services, udpRelay)
		default:
			return fmt.Errorf("failed to create UDP relay service for %s: %w", serverConfig.Name, err)
		}
	}

	for _, service := range sc.services {
		if err := service.Start(); err != nil {
			return fmt.Errorf("failed to start %s: %w", service.String(), err)
		}
	}

	return nil
}

// Stop stops all running services.
func (sc *Config) Stop() {
	for _, s := range sc.services {
		if err := s.Stop(); err != nil {
			sc.logger.Warn("An error occurred while stopping service",
				zap.Stringer("service", s),
				zap.NamedError("stopError", err),
			)
		}
		sc.logger.Info("Stopped service", zap.Stringer("service", s))
	}

	if err := sc.router.Stop(); err != nil {
		sc.logger.Warn("An error occurred while stopping router", zap.NamedError("stopError", err))
	}
}

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/clientgroups"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

var errNetworkDisabled = errors.New("this network (tcp or udp) is disabled")

// Config is the main configuration structure.
// It may be marshaled as or unmarshaled from JSON.
type Config struct {
	Servers      []ServerConfig                   `json:"servers,omitzero"`
	Clients      []ClientConfig                   `json:"clients,omitzero"`
	ClientGroups []clientgroups.ClientGroupConfig `json:"clientGroups,omitzero"`
	DNS          []dns.ResolverConfig             `json:"dns,omitzero"`
	Router       router.Config                    `json:"router,omitzero"`
	Stats        stats.Config                     `json:"stats,omitzero"` // obsolete
	API          api.Config                       `json:"api,omitzero"`
	TLSCerts     tlscerts.Config                  `json:"certs,omitzero"`
}

// Migrate migrates deprecated fields to their new equivalents
// and removes obsolete fields from the configuration.
func (cfg *Config) Migrate() {
	for i := range cfg.Servers {
		sc := &cfg.Servers[i]

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
				NATTimeout: jsoncfg.Duration(time.Duration(sc.NatTimeoutSec) * time.Second),
			})
		}

		sc.Listen = ""
		sc.ListenerFwmark = 0
		sc.ListenerTrafficClass = 0

		sc.EnableTCP = false
		sc.ListenerTFO = false
		sc.DisableInitialPayloadWait = false

		sc.EnableUDP = false
		sc.NatTimeoutSec = 0
		sc.UDPBatchMode = ""
		sc.UDPRelayBatchSize = 0
		sc.UDPServerRecvBatchSize = 0
		sc.UDPSendChannelCapacity = 0
	}

	cfg.Stats.Enabled = false
}

// Manager initializes the service manager.
//
// Initialization order: clients -> DNS -> router -> servers
func (sc *Config) Manager(logger *zap.Logger) (*Manager, error) {
	if len(sc.Servers) == 0 {
		return nil, errors.New("no services to start")
	}

	if len(sc.Clients) == 0 {
		sc.Clients = []ClientConfig{
			{
				Name:                "direct",
				Protocol:            "direct",
				EnableTCP:           true,
				DialerTFO:           true,
				TCPFastOpenFallback: true,
				EnableUDP:           true,
				MTU:                 1500,
			},
		}
	}

	if sc.Stats.Enabled {
		logger.Warn("The global stats configuration is obsolete and will be removed in a future version")
	}

	tlsCertStore, err := sc.TLSCerts.NewStore()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate store: %w", err)
	}

	listenConfigCache := conn.NewListenConfigCache()
	dialerCache := conn.NewDialerCache()
	clientIndexByName := make(map[string]int, len(sc.Clients))
	tcpClientMap := make(map[string]netio.StreamClient, len(sc.Clients))
	udpClientMap := make(map[string]zerocopy.UDPClient, len(sc.Clients))
	var maxClientPackerHeadroom zerocopy.Headroom

	for i := range sc.Clients {
		clientConfig := &sc.Clients[i]

		if dupIndex, ok := clientIndexByName[clientConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate client name: %q (index %d and %d)", clientConfig.Name, dupIndex, i)
		}
		clientIndexByName[clientConfig.Name] = i

		if err := clientConfig.Initialize(tlsCertStore, listenConfigCache, dialerCache, logger); err != nil {
			return nil, fmt.Errorf("failed to initialize client %q: %w", clientConfig.Name, err)
		}

		tcpClient, err := clientConfig.TCPClient()
		switch err {
		case errNetworkDisabled:
		case nil:
			tcpClientMap[clientConfig.Name] = tcpClient
		default:
			return nil, fmt.Errorf("failed to create TCP client for %q: %w", clientConfig.Name, err)
		}

		udpClient, err := clientConfig.UDPClient()
		switch err {
		case errNetworkDisabled:
		case nil:
			udpClientMap[clientConfig.Name] = udpClient
			maxClientPackerHeadroom = zerocopy.MaxHeadroom(maxClientPackerHeadroom, udpClient.Info().PackerHeadroom)
		default:
			return nil, fmt.Errorf("failed to create UDP client for %q: %w", clientConfig.Name, err)
		}
	}

	services := make([]shadowsocks.Service, 0, len(sc.ClientGroups)+2+2*len(sc.Servers))

	clientGroupIndexByName := make(map[string]int, len(sc.ClientGroups))

	for i := range sc.ClientGroups {
		clientGroupConfig := &sc.ClientGroups[i]

		if dupIndex, ok := clientIndexByName[clientGroupConfig.Name]; ok {
			return nil, fmt.Errorf("client group %q (index %d) has the same name as a client (index %d)", clientGroupConfig.Name, i, dupIndex)
		}
		if dupIndex, ok := clientGroupIndexByName[clientGroupConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate client group name: %q (index %d and %d)", clientGroupConfig.Name, dupIndex, i)
		}
		clientGroupIndexByName[clientGroupConfig.Name] = i

		if err := clientGroupConfig.AddClientGroup(logger, tcpClientMap, udpClientMap, func(ps shadowsocks.Service) {
			services = append(services, ps)
		}); err != nil {
			return nil, fmt.Errorf("failed to add client group %q: %w", clientGroupConfig.Name, err)
		}
	}

	resolvers := make([]dns.SimpleResolver, len(sc.DNS))
	resolverMap := make(map[string]dns.SimpleResolver, len(sc.DNS))

	for i := range sc.DNS {
		resolverConfig := &sc.DNS[i]

		if _, ok := resolverMap[resolverConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate DNS resolver name: %q", resolverConfig.Name)
		}

		resolver, err := resolverConfig.NewSimpleResolver(tcpClientMap, udpClientMap, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS resolver %q: %w", resolverConfig.Name, err)
		}

		resolvers[i] = resolver
		resolverMap[resolverConfig.Name] = resolver
	}

	serverIndexByName := make(map[string]int, len(sc.Servers))

	for i := range sc.Servers {
		serverConfig := &sc.Servers[i]
		if dupIndex, ok := serverIndexByName[serverConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate server name: %q (index %d and %d)", serverConfig.Name, dupIndex, i)
		}
		serverIndexByName[serverConfig.Name] = i
	}

	router, err := sc.Router.Router(logger, resolvers, resolverMap, tcpClientMap, udpClientMap, serverIndexByName)
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}

	credman := cred.NewManager(logger)
	services = append(services, credman)

	var (
		apiSM       *ssm.ServerManager
		statsConfig stats.Config
	)

	if sc.API.Enabled {
		statsConfig.Enabled = true

		var apiServer *api.Server
		apiServer, apiSM, err = sc.API.NewServer(logger, listenConfigCache, tlsCertStore)
		if err != nil {
			return nil, fmt.Errorf("failed to create API server: %w", err)
		}
		services = append(services, apiServer)
	}

	for i := range sc.Servers {
		serverConfig := &sc.Servers[i]

		if err := serverConfig.Initialize(tlsCertStore, listenConfigCache, statsConfig, router, logger, i); err != nil {
			return nil, fmt.Errorf("failed to initialize server %q: %w", serverConfig.Name, err)
		}

		tcpRelay, err := serverConfig.TCPRelay()
		switch err {
		case errNetworkDisabled:
		case nil:
			services = append(services, tcpRelay)
		default:
			return nil, fmt.Errorf("failed to create TCP relay service for %q: %w", serverConfig.Name, err)
		}

		udpRelay, err := serverConfig.UDPRelay(maxClientPackerHeadroom)
		switch err {
		case errNetworkDisabled:
		case nil:
			services = append(services, udpRelay)
		default:
			return nil, fmt.Errorf("failed to create UDP relay service for %q: %w", serverConfig.Name, err)
		}

		if err = serverConfig.PostInit(credman, apiSM); err != nil {
			return nil, fmt.Errorf("failed to post-initialize server %q: %w", serverConfig.Name, err)
		}
	}

	return &Manager{services, router, logger}, nil
}

// Manager manages the services.
type Manager struct {
	services []shadowsocks.Service
	router   *router.Router
	logger   *zap.Logger
}

// Start starts all configured services.
func (m *Manager) Start(ctx context.Context) error {
	for _, s := range m.services {
		if err := s.Start(ctx); err != nil {
			kv := s.ZapField()
			return fmt.Errorf("failed to start %s=%q: %w", kv.Key, kv.String, err)
		}
	}
	return nil
}

// Stop stops all running services.
func (m *Manager) Stop() {
	for _, s := range m.services {
		kv := s.ZapField()
		if err := s.Stop(); err != nil {
			m.logger.Warn("Failed to stop service", kv, zap.Error(err))
			continue
		}
		m.logger.Info("Stopped service", kv)
	}
}

// Close closes the manager.
func (m *Manager) Close() {
	if err := m.router.Close(); err != nil {
		m.logger.Warn("Failed to close router", zap.Error(err))
	}
}

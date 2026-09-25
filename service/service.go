package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/clientgroup"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// Config is the main configuration structure.
type Config struct {
	// Servers is the list of server configurations.
	Servers []ServerConfig `json:"servers,omitzero"`

	// Clients is the list of client configurations.
	Clients []ClientConfig `json:"clients,omitzero"`

	// ClientGroups is the list of client group configurations.
	ClientGroups []clientgroup.Config `json:"clientGroups,omitzero"`

	// DNS is the list of DNS resolver configurations.
	DNS []dns.ResolverConfig `json:"dns,omitzero"`

	// Router is the configuration for the router.
	Router router.Config `json:"router,omitzero"`

	// API is the configuration for the HTTP API.
	API api.Config `json:"api,omitzero"`

	// TLSCerts is the configuration for the TLS certificate store.
	TLSCerts tlscerts.Config `json:"certs,omitzero"`
}

// Migrate migrates deprecated fields to their new equivalents
// and removes obsolete fields from the configuration.
func (cfg *Config) Migrate() {
	cfgServers := cfg.Servers
	for i := range cfgServers {
		sc := &cfgServers[i]

		if sc.EnableTCP {
			sc.TCPListeners = append(sc.TCPListeners, TCPListenerConfig{
				Network:                   "tcp",
				Address:                   sc.Listen,
				Fwmark:                    sc.ListenerFwmark,
				TrafficClass:              sc.ListenerTrafficClass,
				FastOpen:                  sc.ListenerTFO,
				DisableInitialPayloadWait: sc.DisableInitialPayloadWait,
			})
		}

		if sc.EnableUDP {
			sc.UDPListeners = append(sc.UDPListeners, UDPListenerConfig{
				Network:             "udp",
				Address:             sc.Listen,
				Fwmark:              sc.ListenerFwmark,
				TrafficClass:        sc.ListenerTrafficClass,
				BatchMode:           sc.UDPBatchMode,
				RelayBatchSize:      sc.UDPRelayBatchSize,
				ServerRecvBatchSize: sc.UDPServerRecvBatchSize,
				SendChannelCapacity: sc.UDPSendChannelCapacity,
				NATTimeout:          jsoncfg.Duration(time.Duration(sc.NatTimeoutSec) * time.Second),
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

	cfgClients := cfg.Clients
	for i := range cfgClients {
		cc := &cfgClients[i]

		if cc.Network != "" {
			if cc.AddressFamilyPreference == netio.AddressFamilyPreferenceDefault {
				switch cc.Network {
				case "ip6":
					cc.AddressFamilyPreference = netio.AddressFamilyPreferenceIPv6Only
				case "ip4":
					cc.AddressFamilyPreference = netio.AddressFamilyPreferenceIPv4Only
				}
			}
			cc.Network = ""
		}
	}
}

// NewManager returns a new service manager.
//
// Initialization order: clients -> DNS -> router -> servers
func (cfg *Config) NewManager(logger *tslog.Logger) (*Manager, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("no services to start")
	}

	if len(cfg.Clients) == 0 {
		cfg.Clients = []ClientConfig{
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

	domainSetByName := make(map[string]domainset.DomainSet, len(cfg.Router.DomainSets))
	domainSetIndexByName := make(map[string]int, len(cfg.Router.DomainSets))

	for i, dsc := range cfg.Router.DomainSets {
		if dupIndex, ok := domainSetIndexByName[dsc.Name]; ok {
			return nil, fmt.Errorf("duplicate domain set name: %q (index %d and %d)", dsc.Name, dupIndex, i)
		}
		domainSetIndexByName[dsc.Name] = i

		domainSet, err := dsc.DomainSet()
		if err != nil {
			return nil, fmt.Errorf("failed to load domain set %q: %w", dsc.Name, err)
		}
		domainSetByName[dsc.Name] = domainSet
	}

	prefixSetByName := make(map[string]*prefixset.PrefixSet, len(cfg.Router.PrefixSets))
	prefixSetIndexByName := make(map[string]int, len(cfg.Router.PrefixSets))

	for i, psc := range cfg.Router.PrefixSets {
		if dupIndex, ok := prefixSetIndexByName[psc.Name]; ok {
			return nil, fmt.Errorf("duplicate prefix set name: %q (index %d and %d)", psc.Name, dupIndex, i)
		}
		prefixSetIndexByName[psc.Name] = i

		prefixSet, err := psc.LoadPrefixSet()
		if err != nil {
			return nil, fmt.Errorf("failed to load prefix set %q: %w", psc.Name, err)
		}
		prefixSetByName[psc.Name] = prefixSet
	}

	tlsCertStore, err := cfg.TLSCerts.NewStore()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate store: %w", err)
	}

	tcpListenConfigCache := conn.NewTCPListenConfigCache()
	tcpDialerCache := conn.NewTCPDialerCache()
	udpSocketConfigCache := conn.NewUDPSocketConfigCache()
	unixDomainSocketConfigCache := conn.NewUnixDomainSocketConfigCache()

	cfgClients := cfg.Clients
	clientIndexByName := make(map[string]int, len(cfgClients))
	tcpClientByName := make(map[string]netio.StreamClient, len(cfgClients))
	udpClientByName := make(map[string]zerocopy.UDPClient, len(cfgClients))

	for i := range cfgClients {
		clientConfig := &cfgClients[i]

		if dupIndex, ok := clientIndexByName[clientConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate client name: %q (index %d and %d)", clientConfig.Name, dupIndex, i)
		}
		clientIndexByName[clientConfig.Name] = i

		if err := clientConfig.AddClient(tcpClientByName, udpClientByName, tcpDialerCache, udpSocketConfigCache, prefixSetByName, tlsCertStore, logger); err != nil {
			return nil, fmt.Errorf("failed to create client %q: %w", clientConfig.Name, err)
		}
	}

	var maxClientPackerHeadroom zerocopy.Headroom
	for _, udpClient := range udpClientByName {
		maxClientPackerHeadroom = zerocopy.MaxHeadroom(maxClientPackerHeadroom, udpClient.Info().PackerHeadroom)
	}

	cfgClientGroups := cfg.ClientGroups
	cfgServers := cfg.Servers
	services := make([]shadowsocks.Service, 0, len(cfgClientGroups)+2+2*len(cfgServers))
	clientGroupIndexByName := make(map[string]int, len(cfgClientGroups))

	for i := range cfgClientGroups {
		clientGroupConfig := &cfgClientGroups[i]

		if dupIndex, ok := clientIndexByName[clientGroupConfig.Name]; ok {
			return nil, fmt.Errorf("client group %q (index %d) has the same name as a client (index %d)", clientGroupConfig.Name, i, dupIndex)
		}
		if dupIndex, ok := clientGroupIndexByName[clientGroupConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate client group name: %q (index %d and %d)", clientGroupConfig.Name, dupIndex, i)
		}
		clientGroupIndexByName[clientGroupConfig.Name] = i

		if err := clientGroupConfig.AddClientGroup(logger, tcpClientByName, udpClientByName, func(ps shadowsocks.Service) {
			services = append(services, ps)
		}); err != nil {
			return nil, fmt.Errorf("failed to add client group %q: %w", clientGroupConfig.Name, err)
		}
	}

	cfgDNS := cfg.DNS
	resolvers := make([]dns.SimpleResolver, len(cfgDNS))
	resolverByName := make(map[string]dns.SimpleResolver, len(cfgDNS))

	for i := range cfgDNS {
		resolverConfig := &cfgDNS[i]

		if _, ok := resolverByName[resolverConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate DNS resolver name: %q", resolverConfig.Name)
		}

		resolver, err := resolverConfig.NewSimpleResolver(tcpClientByName, udpClientByName, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS resolver %q: %w", resolverConfig.Name, err)
		}

		resolvers[i] = resolver
		resolverByName[resolverConfig.Name] = resolver
	}

	serverIndexByName := make(map[string]int, len(cfgServers))

	for i := range cfgServers {
		serverConfig := &cfgServers[i]
		if dupIndex, ok := serverIndexByName[serverConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate server name: %q (index %d and %d)", serverConfig.Name, dupIndex, i)
		}
		serverIndexByName[serverConfig.Name] = i
	}

	router, err := cfg.Router.Router(logger, resolvers, resolverByName, tcpClientByName, udpClientByName, serverIndexByName, domainSetByName, prefixSetByName)
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}

	credmgr := cred.NewManager(logger)

	var (
		serverByName map[string]ssm.Server
		serverNames  []string
		statsConfig  stats.Config
	)

	if cfg.API.Enabled {
		serverByName = make(map[string]ssm.Server, len(cfgServers))
		serverNames = make([]string, len(cfgServers))
		statsConfig.Enabled = true
	}

	for i := range cfgServers {
		serverConfig := &cfgServers[i]

		if err := serverConfig.Initialize(tlsCertStore, tcpListenConfigCache, udpSocketConfigCache, unixDomainSocketConfigCache, statsConfig, router, logger, i); err != nil {
			return nil, fmt.Errorf("failed to initialize server %q: %w", serverConfig.Name, err)
		}

		if len(serverConfig.TCPListeners) > 0 || len(serverConfig.UnixListeners) > 0 {
			tcpRelay, err := serverConfig.TCPRelay()
			if err != nil {
				return nil, fmt.Errorf("failed to create TCP relay service for %q: %w", serverConfig.Name, err)
			}
			services = append(services, tcpRelay)
		}

		if len(serverConfig.UDPListeners) > 0 {
			udpRelay, err := serverConfig.UDPRelay(logger, maxClientPackerHeadroom)
			if err != nil {
				return nil, fmt.Errorf("failed to create UDP relay service for %q: %w", serverConfig.Name, err)
			}
			services = append(services, udpRelay)
		}

		if err = serverConfig.PostInit(credmgr, serverByName, serverNames); err != nil {
			return nil, fmt.Errorf("failed to post-initialize server %q: %w", serverConfig.Name, err)
		}
	}

	services = credmgr.AppendService(services)

	if cfg.API.Enabled {
		apiServer, err := cfg.API.NewServer(logger, tcpListenConfigCache, tlsCertStore, serverByName, serverNames)
		if err != nil {
			return nil, fmt.Errorf("failed to create API server: %w", err)
		}
		services = append(services, apiServer)
	}

	return &Manager{
		notifyReload: newReloadNotifier(logger, credmgr, tlsCertStore),
		services:     services,
		router:       router,
		logger:       logger,
	}, nil
}

// Manager manages the services.
type Manager struct {
	notifyReload reloadNotifier
	services     []shadowsocks.Service
	router       *router.Router
	logger       *tslog.Logger
}

// Run starts all services. If any service fails to start, it stops all running services
// and returns false. On success, it blocks until the context is canceled, and then stops
// all services. It returns true if no errors were encountered.
func (m *Manager) Run(ctx context.Context) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	m.notifyReload.start()

	ok := true
	runningSvcs := make([]shadowsocks.Service, 0, len(m.services))

	for _, s := range m.services {
		if err := s.Start(ctx); err != nil {
			m.logger.Error("Failed to start service", s.SlogAttr(), tslog.Err(err))
			ok = false
			break
		}
		runningSvcs = append(runningSvcs, s)
	}

	var stopReason slog.Attr
	if ok {
		<-ctx.Done()
		stopReason = slog.Any("reason", context.Cause(ctx))
	} else {
		cancel()
		stopReason = slog.String("reason", "one or more services failed to start")
	}
	m.logger.Info("Stopping services", stopReason)

	for _, s := range runningSvcs {
		if err := s.Stop(); err != nil {
			m.logger.Error("Failed to stop service", s.SlogAttr(), tslog.Err(err))
		}
	}

	m.notifyReload.stop()
	return ok
}

// Close closes the manager.
func (m *Manager) Close() {
	if err := m.router.Close(); err != nil {
		m.logger.Error("Failed to close router", tslog.Err(err))
	}
}

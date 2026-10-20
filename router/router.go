package router

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang/v2"
)

// Config is the configuration for a Router.
type Config struct {
	DefaultTCPClientName  string             `json:"defaultTCPClientName,omitzero"`
	DefaultUDPClientName  string             `json:"defaultUDPClientName,omitzero"`
	GeoLite2CountryDbPath string             `json:"geoLite2CountryDbPath,omitzero"`
	DomainSets            []domainset.Config `json:"domainSets,omitzero"`
	PrefixSets            []prefixset.Config `json:"prefixSets,omitzero"`
	Routes                []RouteConfig      `json:"routes,omitzero"`
}

// ConfigMergeState keeps track of the merged state across multiple [Config] instances.
type ConfigMergeState struct {
	domainSets []domainset.Config
	prefixSets []prefixset.Config
	routes     []RouteConfig
}

// Update adds cfg to the merged state and prepares cfg for the next unmarshaling operation.
func (s *ConfigMergeState) Update(cfg *Config) {
	if len(cfg.DomainSets) > 0 {
		if len(s.domainSets) > 0 {
			s.domainSets = append(s.domainSets, cfg.DomainSets...)
		} else {
			s.domainSets = cfg.DomainSets
		}
		cfg.DomainSets = s.domainSets[len(s.domainSets):]
	}

	if len(cfg.PrefixSets) > 0 {
		if len(s.prefixSets) > 0 {
			s.prefixSets = append(s.prefixSets, cfg.PrefixSets...)
		} else {
			s.prefixSets = cfg.PrefixSets
		}
		cfg.PrefixSets = s.prefixSets[len(s.prefixSets):]
	}

	if len(cfg.Routes) > 0 {
		if len(s.routes) > 0 {
			s.routes = append(s.routes, cfg.Routes...)
		} else {
			s.routes = cfg.Routes
		}
		cfg.Routes = s.routes[len(s.routes):]
	}
}

// Finalize applies the merged state to cfg.
func (s *ConfigMergeState) Finalize(cfg *Config) {
	if len(s.domainSets) > 0 {
		if len(cfg.DomainSets) > 0 {
			cfg.DomainSets = append(s.domainSets, cfg.DomainSets...)
		} else {
			cfg.DomainSets = s.domainSets
		}
	}

	if len(s.prefixSets) > 0 {
		if len(cfg.PrefixSets) > 0 {
			cfg.PrefixSets = append(s.prefixSets, cfg.PrefixSets...)
		} else {
			cfg.PrefixSets = s.prefixSets
		}
	}

	if len(s.routes) > 0 {
		if len(cfg.Routes) > 0 {
			cfg.Routes = append(s.routes, cfg.Routes...)
		} else {
			cfg.Routes = s.routes
		}
	}
}

// Router creates a router from the RouterConfig.
func (cfg *Config) Router(
	logger *tslog.Logger,
	resolvers []dns.SimpleResolver,
	resolverMap map[string]dns.SimpleResolver,
	tcpClientMap map[string]netio.StreamClient,
	udpClientMap map[string]zerocopy.UDPClient,
	serverIndexByName map[string]int,
	domainSetByName map[string]domainset.DomainSet,
	prefixSetByName map[string]*prefixset.PrefixSet,
) (r *Router, err error) {
	var defaultTCPClient netio.StreamClient
	switch name := cfg.DefaultTCPClientName; {
	case name != "" || len(tcpClientMap) > 1:
		defaultTCPClient = tcpClientMap[name]
		if defaultTCPClient == nil && name != "reject" {
			return nil, fmt.Errorf("default TCP client not found: %q", name)
		}
	case len(tcpClientMap) == 1:
		for _, tcpClient := range tcpClientMap {
			defaultTCPClient = tcpClient
		}
	}

	var defaultUDPClient zerocopy.UDPClient
	switch name := cfg.DefaultUDPClientName; {
	case name != "" || len(udpClientMap) > 1:
		defaultUDPClient = udpClientMap[name]
		if defaultUDPClient == nil && name != "reject" {
			return nil, fmt.Errorf("default UDP client not found: %q", name)
		}
	case len(udpClientMap) == 1:
		for _, udpClient := range udpClientMap {
			defaultUDPClient = udpClient
		}
	}

	var (
		geoip *geoip2.Reader
		close = func() error { return nil }
	)

	if path := cfg.GeoLite2CountryDbPath; path != "" {
		var data []byte
		data, close, err = mmap.ReadFile[[]byte](path)
		if err != nil {
			return nil, fmt.Errorf("failed to read GeoLite2-Country database: %w", err)
		}
		defer func() {
			if err != nil {
				_ = close()
			}
		}()

		geoip, err = geoip2.OpenBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to open GeoLite2-Country database: %w", err)
		}

		if logger.Enabled(slog.LevelDebug) {
			metadata := geoip.Metadata()
			logger.Debug("Loaded GeoLite2-Country database",
				slog.String("databaseType", metadata.DatabaseType),
				slog.Time("buildTime", metadata.BuildTime()),
			)
		}
	}

	cfgRoutes := cfg.Routes
	routes := make([]Route, len(cfgRoutes))

	for i := range cfgRoutes {
		routeCfg := &cfgRoutes[i]
		route, err := routeCfg.NewRoute(
			geoip,
			logger,
			resolvers,
			resolverMap,
			tcpClientMap,
			udpClientMap,
			serverIndexByName,
			domainSetByName,
			prefixSetByName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create route %q at index %d: %w", routeCfg.Name, i, err)
		}
		routes[i] = route
	}

	return &Router{
		geoip:  geoip,
		close:  close,
		logger: logger,
		routes: routes,
		defaultRoute: Route{
			name:      "default",
			tcpClient: defaultTCPClient,
			udpClient: defaultUDPClient,
		},
	}, nil
}

// Router looks up the destination client for requests received by servers.
type Router struct {
	geoip        *geoip2.Reader
	close        func() error
	logger       *tslog.Logger
	routes       []Route
	defaultRoute Route
}

// Close closes the router.
func (r *Router) Close() error {
	return r.close()
}

// GetTCPClient returns the [netio.StreamClient] for a TCP request received by server
// from sourceAddrPort to targetAddr.
func (r *Router) GetTCPClient(ctx context.Context, requestInfo RequestInfo) (netio.StreamClient, error) {
	route, err := r.match(ctx, protocolTCP, requestInfo)
	if err != nil {
		return nil, err
	}

	if r.logger.Enabled(slog.LevelDebug) {
		r.logger.Debug("Matched route for TCP connection",
			slog.Int("serverIndex", requestInfo.ServerIndex),
			slog.String("username", requestInfo.Username),
			tslog.AddrPort("sourceAddrPort", requestInfo.SourceAddrPort),
			tslog.ConnAddr("targetAddress", requestInfo.TargetAddr),
			slog.String("route", route.name),
		)
	}

	return route.TCPClient()
}

// GetUDPClient returns the zerocopy.UDPClient for a UDP session received by server.
// The first received packet of the session is from sourceAddrPort to targetAddr.
func (r *Router) GetUDPClient(ctx context.Context, requestInfo RequestInfo) (zerocopy.UDPClient, error) {
	route, err := r.match(ctx, protocolUDP, requestInfo)
	if err != nil {
		return nil, err
	}

	if r.logger.Enabled(slog.LevelDebug) {
		r.logger.Debug("Matched route for UDP session",
			slog.Int("serverIndex", requestInfo.ServerIndex),
			slog.String("username", requestInfo.Username),
			tslog.AddrPort("sourceAddrPort", requestInfo.SourceAddrPort),
			tslog.ConnAddr("targetAddress", requestInfo.TargetAddr),
			slog.String("route", route.name),
		)
	}

	return route.UDPClient()
}

// match returns the matched route for the new TCP request or UDP session.
func (r *Router) match(ctx context.Context, network protocol, requestInfo RequestInfo) (*Route, error) {
	for i := range r.routes {
		matched, err := r.routes[i].Match(ctx, network, requestInfo)
		if err != nil {
			return nil, err
		}
		if matched {
			return &r.routes[i], nil
		}
	}
	return &r.defaultRoute, nil
}

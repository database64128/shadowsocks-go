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

// Merge merges other into cfg.
//
// Non-empty string fields in other overwrite the corresponding fields in cfg.
//
// For slice fields, if the slice in cfg is empty but the slice in other is non-empty,
// the non-empty slice from other is used without cloning; if both are non-empty,
// the slice from other is appended to the slice in cfg.
func (cfg *Config) Merge(other *Config) {
	if other.DefaultTCPClientName != "" {
		cfg.DefaultTCPClientName = other.DefaultTCPClientName
	}

	if other.DefaultUDPClientName != "" {
		cfg.DefaultUDPClientName = other.DefaultUDPClientName
	}

	if other.GeoLite2CountryDbPath != "" {
		cfg.GeoLite2CountryDbPath = other.GeoLite2CountryDbPath
	}

	if len(other.DomainSets) > 0 {
		if len(cfg.DomainSets) > 0 {
			cfg.DomainSets = append(cfg.DomainSets, other.DomainSets...)
		} else {
			cfg.DomainSets = other.DomainSets
		}
	}

	if len(other.PrefixSets) > 0 {
		if len(cfg.PrefixSets) > 0 {
			cfg.PrefixSets = append(cfg.PrefixSets, other.PrefixSets...)
		} else {
			cfg.PrefixSets = other.PrefixSets
		}
	}

	if len(other.Routes) > 0 {
		if len(cfg.Routes) > 0 {
			cfg.Routes = append(cfg.Routes, other.Routes...)
		} else {
			cfg.Routes = other.Routes
		}
	}
}

// Router creates a router from the RouterConfig.
func (rc *Config) Router(
	logger *tslog.Logger,
	resolvers []dns.SimpleResolver,
	resolverMap map[string]dns.SimpleResolver,
	tcpClientMap map[string]netio.StreamClient,
	udpClientMap map[string]zerocopy.UDPClient,
	serverIndexByName map[string]int,
	domainSetByName map[string]domainset.DomainSet,
	prefixSetByName map[string]*prefixset.PrefixSet,
) (r *Router, err error) {
	defaultRoute := Route{name: "default"}

	if rc.DefaultTCPClientName == "" && len(tcpClientMap) == 1 {
		for _, tcpClient := range tcpClientMap {
			defaultRoute.tcpClient = tcpClient
		}
	} else {
		defaultRoute.tcpClient = tcpClientMap[rc.DefaultTCPClientName]
		if defaultRoute.tcpClient == nil && rc.DefaultTCPClientName != "reject" {
			return nil, fmt.Errorf("default TCP client not found: %q", rc.DefaultTCPClientName)
		}
	}

	if rc.DefaultUDPClientName == "" && len(udpClientMap) == 1 {
		for _, udpClient := range udpClientMap {
			defaultRoute.udpClient = udpClient
		}
	} else {
		defaultRoute.udpClient = udpClientMap[rc.DefaultUDPClientName]
		if defaultRoute.udpClient == nil && rc.DefaultUDPClientName != "reject" {
			return nil, fmt.Errorf("default UDP client not found: %q", rc.DefaultUDPClientName)
		}
	}

	var (
		geoip *geoip2.Reader
		close = func() error { return nil }
	)

	if rc.GeoLite2CountryDbPath != "" {
		var data []byte
		data, close, err = mmap.ReadFile[[]byte](rc.GeoLite2CountryDbPath)
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
			return nil, err
		}
	}

	routes := make([]Route, len(rc.Routes)+1)

	for i := range rc.Routes {
		route, err := rc.Routes[i].Route(geoip, logger, resolvers, resolverMap, tcpClientMap, udpClientMap, serverIndexByName, domainSetByName, prefixSetByName)
		if err != nil {
			return nil, err
		}
		routes[i] = route
	}

	routes[len(rc.Routes)] = defaultRoute

	return &Router{
		geoip:  geoip,
		close:  close,
		logger: logger,
		routes: routes,
	}, nil
}

// Router looks up the destination client for requests received by servers.
type Router struct {
	geoip  *geoip2.Reader
	close  func() error
	logger *tslog.Logger
	routes []Route
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
	panic("did not match default route")
}

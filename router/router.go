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

	switch rc.DefaultTCPClientName {
	case "reject":
	case "":
		if len(tcpClientMap) == 1 {
			for _, tcpClient := range tcpClientMap {
				defaultRoute.tcpClient = tcpClient
			}
		}
	default:
		defaultRoute.tcpClient = tcpClientMap[rc.DefaultTCPClientName]
		if defaultRoute.tcpClient == nil {
			return nil, fmt.Errorf("default TCP client not found: %q", rc.DefaultTCPClientName)
		}
	}

	switch rc.DefaultUDPClientName {
	case "reject":
	case "":
		if len(udpClientMap) == 1 {
			for _, udpClient := range udpClientMap {
				defaultRoute.udpClient = udpClient
			}
		}
	default:
		defaultRoute.udpClient = udpClientMap[rc.DefaultUDPClientName]
		if defaultRoute.udpClient == nil {
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

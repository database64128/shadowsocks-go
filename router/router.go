package router

import (
	"context"
	"fmt"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
	"go4.org/netipx"
)

// Config is the configuration for a Router.
type Config struct {
	DefaultTCPClientName  string             `json:"defaultTCPClientName"`
	DefaultUDPClientName  string             `json:"defaultUDPClientName"`
	GeoLite2CountryDbPath string             `json:"geoLite2CountryDbPath"`
	DomainSets            []domainset.Config `json:"domainSets"`
	PrefixSets            []prefixset.Config `json:"prefixSets"`
	Routes                []RouteConfig      `json:"routes"`
}

// Router creates a router from the RouterConfig.
func (rc *Config) Router(logger *zap.Logger, resolvers []dns.SimpleResolver, resolverMap map[string]dns.SimpleResolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, serverIndexByName map[string]int) (r *Router, err error) {
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

		geoip, err = geoip2.FromBytes(data)
		if err != nil {
			return nil, err
		}
	}

	domainSetMap := make(map[string]domainset.DomainSet, len(rc.DomainSets))

	for _, dsc := range rc.DomainSets {
		domainSet, err := dsc.DomainSet()
		if err != nil {
			return nil, fmt.Errorf("failed to load domain set %q: %w", dsc.Name, err)
		}
		domainSetMap[dsc.Name] = domainSet
	}

	prefixSetMap := make(map[string]*netipx.IPSet, len(rc.PrefixSets))

	for _, psc := range rc.PrefixSets {
		s, err := psc.IPSet()
		if err != nil {
			return nil, fmt.Errorf("failed to load prefix set %q: %w", psc.Name, err)
		}
		prefixSetMap[psc.Name] = s
	}

	routes := make([]Route, len(rc.Routes)+1)

	for i := range rc.Routes {
		route, err := rc.Routes[i].Route(geoip, logger, resolvers, resolverMap, tcpClientMap, udpClientMap, serverIndexByName, domainSetMap, prefixSetMap)
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
	logger *zap.Logger
	routes []Route
}

// Close closes the router.
func (r *Router) Close() error {
	return r.close()
}

// GetTCPClient returns the zerocopy.TCPClient for a TCP request received by server
// from sourceAddrPort to targetAddr.
func (r *Router) GetTCPClient(ctx context.Context, requestInfo RequestInfo) (zerocopy.TCPClient, error) {
	route, err := r.match(ctx, protocolTCP, requestInfo)
	if err != nil {
		return nil, err
	}

	if ce := r.logger.Check(zap.DebugLevel, "Matched route for TCP connection"); ce != nil {
		ce.Write(
			zap.Int("serverIndex", requestInfo.ServerIndex),
			zap.String("username", requestInfo.Username),
			zap.Stringer("sourceAddrPort", requestInfo.SourceAddrPort),
			zap.Stringer("targetAddress", requestInfo.TargetAddr),
			zap.Stringer("route", route),
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

	if ce := r.logger.Check(zap.DebugLevel, "Matched route for UDP session"); ce != nil {
		ce.Write(
			zap.Int("serverIndex", requestInfo.ServerIndex),
			zap.String("username", requestInfo.Username),
			zap.Stringer("sourceAddrPort", requestInfo.SourceAddrPort),
			zap.Stringer("targetAddress", requestInfo.TargetAddr),
			zap.Stringer("route", route),
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

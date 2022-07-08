package router

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

var (
	ErrRejected     = errors.New("rejected")
	errDefaultRoute = errors.New("default route")
	errNoGeoLite2Db = errors.New("missing GeoLite2 country database path")
)

// RouterConfig is the configuration for a Router.
type RouterConfig struct {
	DisableNameResolutionForIPRules bool              `json:"disableNameResolutionForIPRules"`
	DefaultTCPClientName            string            `json:"defaultTCPClientName"`
	DefaultUDPClientName            string            `json:"defaultUDPClientName"`
	GeoLite2CountryDbPath           string            `json:"geoLite2CountryDbPath"`
	DomainSets                      []DomainSetConfig `json:"domainSets"`
	Routes                          []RouteConfig     `json:"routes"`
}

// Router creates a router from the RouterConfig.
func (rc *RouterConfig) Router(logger *zap.Logger, resolverNames []string, resolverMap map[string]*dns.Resolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient) (*Router, error) {
	if len(resolverNames) == 0 {
		rc.DisableNameResolutionForIPRules = true
	}

	if rc.DefaultTCPClientName == "" && len(tcpClientMap) == 1 {
		for name := range tcpClientMap {
			rc.DefaultTCPClientName = name
		}
	}

	if rc.DefaultUDPClientName == "" && len(udpClientMap) == 1 {
		for name := range udpClientMap {
			rc.DefaultUDPClientName = name
		}
	}

	var (
		defaultTCPClient zerocopy.TCPClient
		defaultUDPClient zerocopy.UDPClient
		geoip            *geoip2.Reader
		ok               bool
		err              error
	)

	switch rc.DefaultTCPClientName {
	case "", "reject":
	default:
		defaultTCPClient, ok = tcpClientMap[rc.DefaultTCPClientName]
		if !ok {
			return nil, fmt.Errorf("default TCP client not found: %s", rc.DefaultTCPClientName)
		}
	}

	switch rc.DefaultUDPClientName {
	case "", "reject":
	default:
		defaultUDPClient, ok = udpClientMap[rc.DefaultUDPClientName]
		if !ok {
			return nil, fmt.Errorf("default UDP client not found: %s", rc.DefaultUDPClientName)
		}
	}

	allowGeoIP := rc.GeoLite2CountryDbPath != ""

	if allowGeoIP {
		geoip, err = geoip2.Open(rc.GeoLite2CountryDbPath)
		if err != nil {
			return nil, err
		}
	}

	domainSetMap := make(map[string]DomainSet, len(rc.DomainSets))

	for _, domainSetConfig := range rc.DomainSets {
		domainSet, err := domainSetConfig.DomainSet()
		if err != nil {
			return nil, err
		}
		domainSetMap[domainSetConfig.Name] = domainSet
	}

	routes := make([]*Route, len(rc.Routes))

	for i := range rc.Routes {
		route, err := rc.Routes[i].Route(allowGeoIP, resolverMap, tcpClientMap, udpClientMap, domainSetMap)
		if err != nil {
			return nil, err
		}
		routes[i] = route
	}

	return NewRouter(rc.DisableNameResolutionForIPRules, geoip, logger, defaultTCPClient, defaultUDPClient, routes, resolverNames, resolverMap), nil
}

// RouteConfig is a routing rule.
type RouteConfig struct {
	// Name of this route. Used in logs to identify matched routes.
	Name string `json:"name"`

	// Apply this route to "tcp" or "udp" only. If empty, match all requests.
	Network string `json:"network"`

	// Route matched requests to this client. Must not be empty.
	ClientName string `json:"clientName"`

	// When matching a domain target to IP prefixes, use this resolver to resolve the domain name.
	// If unspecified, use all resolvers by order.
	ResolverName string `json:"resolverName"`

	// Match requests from these servers. If empty, match all requests.
	ServerNames []string `json:"serverNames"`

	// Match requests to these domain targets. If empty, match all requests.
	Domains []string `json:"domains"`

	// Match requests to domains in these domain sets. If empty, match all requests.
	DomainSets []string `json:"domainSets"`

	// Match requests to these IP prefixes. If empty, match all requests.
	Prefixes []netip.Prefix `json:"prefixes"`

	// Match requests from these IP prefixes. If empty, match all requests.
	SourcePrefixes []netip.Prefix `json:"sourcePrefixes"`

	// Match requests to these ports. If empty, match all requests.
	Ports []uint16 `json:"ports"`

	// Match requests from these ports. If empty, match all requests.
	SourcePorts []uint16 `json:"sourcePorts"`

	// Match requests to IP addresses in these countries. If empty, match all requests.
	GeoIPCountries []string `json:"geoIPCountries"`

	// Invert domain matching logic. Match requests to all domains except those in Domains or DomainSets.
	InvertDomains bool `json:"invertDomains"`

	// Invert IP prefix matching logic. Match requests to all IP prefixes except those in Prefixes.
	InvertPrefixes bool `json:"invertPrefixes"`

	// Invert port matching logic. Match requests to all ports except those in Ports.
	InvertPorts bool `json:"invertPorts"`

	// Invert source IP prefix matching logic. Match requests from all IP prefixes except those in SourcePrefixes.
	InvertSourcePrefixes bool `json:"invertSourcePrefixes"`

	// Invert source port matching logic. Match requests from all ports except those in SourcePorts.
	InvertSourcePorts bool `json:"invertSourcePorts"`

	// Invert GeoIP country matching logic. Match requests to all IP addresses except those in GeoIPCountries.
	InvertGeoIPCountries bool `json:"invertGeoIPCountries"`
}

// Route creates a route from the RouteConfig.
func (rc *RouteConfig) Route(allowGeoIP bool, resolverMap map[string]*dns.Resolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, domainSetMap map[string]DomainSet) (*Route, error) {
	if !allowGeoIP && len(rc.GeoIPCountries) > 0 {
		return nil, errNoGeoLite2Db
	}

	switch rc.Network {
	case "", "tcp", "udp":
	default:
		return nil, fmt.Errorf("invalid network: %s", rc.Network)
	}

	var (
		resolver *dns.Resolver
		ok       bool
	)

	if rc.ResolverName != "" {
		resolver, ok = resolverMap[rc.ResolverName]
		if !ok {
			return nil, fmt.Errorf("resolver not found: %s", rc.ResolverName)
		}
	}

	var defaultDomainSetCount int

	if len(rc.Domains) > 0 {
		defaultDomainSetCount = 1
	}

	domainSets := make([]DomainSet, defaultDomainSetCount+len(rc.DomainSets))

	if defaultDomainSetCount == 1 {
		domainSets[0] = DomainSet{
			Domains: rc.Domains,
		}
	}

	for i, dsc := range rc.DomainSets {
		ds, ok := domainSetMap[dsc]
		if !ok {
			return nil, fmt.Errorf("domain set not found: %s", dsc)
		}
		domainSets[defaultDomainSetCount+i] = ds
	}

	route := Route{
		config:     rc,
		resolver:   resolver,
		domainSets: domainSets,
	}

	if rc.ClientName == "reject" {
		return &route, nil
	}

	switch rc.Network {
	case "", "tcp":
		route.tcpClient, ok = tcpClientMap[rc.ClientName]
		if !ok {
			return nil, fmt.Errorf("TCP client not found: %s", rc.ClientName)
		}
	}

	switch rc.Network {
	case "", "udp":
		route.udpClient, ok = udpClientMap[rc.ClientName]
		if !ok {
			return nil, fmt.Errorf("UDP client not found: %s", rc.ClientName)
		}
	}

	return &route, nil
}

// Route controls where a request is routed.
type Route struct {
	config     *RouteConfig
	resolver   *dns.Resolver
	tcpClient  zerocopy.TCPClient
	udpClient  zerocopy.UDPClient
	domainSets []DomainSet
}

// Router looks up the destination client for requests received by servers.
type Router struct {
	disableNameResolutionForIPRules bool
	geoip                           *geoip2.Reader
	logger                          *zap.Logger
	defaultTCPClient                zerocopy.TCPClient
	defaultUDPClient                zerocopy.UDPClient
	routes                          []*Route
	resolverNames                   []string
	resolverMap                     map[string]*dns.Resolver
}

func NewRouter(disableNameResolutionForIPRules bool, geoip *geoip2.Reader, logger *zap.Logger, defaultTCPClient zerocopy.TCPClient, defaultUDPClient zerocopy.UDPClient, routes []*Route, resolverNames []string, resolverMap map[string]*dns.Resolver) *Router {
	return &Router{
		disableNameResolutionForIPRules: disableNameResolutionForIPRules,
		geoip:                           geoip,
		logger:                          logger,
		defaultTCPClient:                defaultTCPClient,
		defaultUDPClient:                defaultUDPClient,
		routes:                          routes,
		resolverNames:                   resolverNames,
		resolverMap:                     resolverMap,
	}
}

// Stop stops the router.
func (r *Router) Stop() error {
	return r.geoip.Close()
}

// GetTCPClient returns the zerocopy.TCPClient for a TCP request received by serverName
// from sourceAddrPort to targetAddr.
func (r *Router) GetTCPClient(serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (tcpClient zerocopy.TCPClient, err error) {
	route, err := r.match("tcp", serverName, sourceAddrPort, targetAddr)
	switch err {
	case nil:
		tcpClient = route.tcpClient
		r.logger.Info("Matched route for TCP connection",
			zap.String("serverName", serverName),
			zap.Stringer("sourceAddrPort", sourceAddrPort),
			zap.Stringer("targetAddress", targetAddr),
			zap.String("routeName", route.config.Name),
			zap.String("clientName", route.config.ClientName),
		)
	case errDefaultRoute:
		tcpClient = r.defaultTCPClient
		err = nil
	default:
		return
	}

	if tcpClient == nil {
		err = ErrRejected
	}
	return
}

// GetUDPClient returns the zerocopy.UDPClient for a UDP session received by serverName.
// The first received packet of the session is from sourceAddrPort to targetAddr.
func (r *Router) GetUDPClient(serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (udpClient zerocopy.UDPClient, err error) {
	route, err := r.match("udp", serverName, sourceAddrPort, targetAddr)
	switch err {
	case nil:
		udpClient = route.udpClient
		r.logger.Info("Matched route for UDP session",
			zap.String("serverName", serverName),
			zap.Stringer("sourceAddrPort", sourceAddrPort),
			zap.Stringer("targetAddress", targetAddr),
			zap.String("routeName", route.config.Name),
			zap.String("clientName", route.config.ClientName),
		)
	case errDefaultRoute:
		udpClient = r.defaultUDPClient
		err = nil
	default:
		return
	}

	if udpClient == nil {
		err = ErrRejected
	}
	return
}

func (r *Router) match(network, serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (*Route, error) {
	for _, route := range r.routes {
		// Network
		switch route.config.Network {
		case "", network:
		default:
			continue
		}

		// ServerNames
		if len(route.config.ServerNames) > 0 && !slices.Contains(route.config.ServerNames, serverName) {
			continue
		}

		// SourcePorts
		if len(route.config.SourcePorts) > 0 && !slices.Contains(route.config.SourcePorts, sourceAddrPort.Port()) != route.config.InvertSourcePorts {
			continue
		}

		// SourcePrefixes
		if len(route.config.SourcePrefixes) > 0 && !matchAddrToPrefixes(route.config.SourcePrefixes, sourceAddrPort.Addr()) != route.config.InvertSourcePrefixes {
			continue
		}

		// Ports
		if len(route.config.Ports) > 0 && !slices.Contains(route.config.Ports, targetAddr.Port()) != route.config.InvertPorts {
			continue
		}

		// Match all domain and IP targets.
		if len(route.domainSets) == 0 && len(route.config.Prefixes) == 0 && len(route.config.GeoIPCountries) == 0 {
			return route, nil
		}

		// Domain sets
		if len(route.domainSets) > 0 && targetAddr.IsDomain() {
			if matchDomainToDomainSets(route.domainSets, targetAddr.Host()) != route.config.InvertDomains {
				return route, nil
			}
		}

		// Prefixes and GeoIP countries
		if len(route.config.Prefixes) == 0 && len(route.config.GeoIPCountries) == 0 {
			continue
		}

		if targetAddr.IsDomain() {
			if r.disableNameResolutionForIPRules {
				continue
			}

			result, err := r.lookup(targetAddr.Host(), route.resolver)
			if err != nil {
				return nil, err
			}

			if len(route.config.Prefixes) > 0 && matchResultToPrefixes(route.config.Prefixes, result) != route.config.InvertPrefixes {
				return route, nil
			}

			if len(route.config.GeoIPCountries) > 0 {
				matched, err := r.matchResultToGeoIPCountries(route.config.GeoIPCountries, result)
				if err != nil {
					return nil, err
				}
				if matched != route.config.InvertGeoIPCountries {
					return route, nil
				}
			}
		} else {
			if len(route.config.Prefixes) > 0 {
				addr, err := targetAddr.Addr(true)
				if err != nil {
					return nil, err
				}

				if matchAddrToPrefixes(route.config.Prefixes, addr) != route.config.InvertPrefixes {
					return route, nil
				}
			}

			if len(route.config.GeoIPCountries) > 0 {
				matched, err := r.matchSocksAddrToGeoIPCountries(route.config.GeoIPCountries, targetAddr)
				if err != nil {
					return nil, err
				}
				if matched != route.config.InvertGeoIPCountries {
					return route, nil
				}
			}
		}
	}

	return nil, errDefaultRoute
}

// lookup looks up the domain name using the specified resolver, or all resolvers if unspecified,
// and returns the lookup result, or an error if the lookup failed.
func (r *Router) lookup(domain string, resolver *dns.Resolver) (dns.Result, error) {
	if resolver != nil {
		return resolver.Lookup(domain)
	}

	for _, resolverName := range r.resolverNames {
		result, err := r.resolverMap[resolverName].Lookup(domain)
		if err != nil {
			if err == dns.ErrLookup {
				continue
			}
			return dns.Result{}, err
		}
		return result, nil
	}

	return dns.Result{}, dns.ErrLookup
}

func (r *Router) matchIPToGeoIPCountries(countries []string, ip net.IP) (bool, error) {
	country, err := r.geoip.Country(ip)
	if err != nil {
		return false, err
	}
	r.logger.Debug("Matched GeoIP country",
		zap.String("ip", ip.String()),
		zap.String("country", country.Country.IsoCode),
	)
	return slices.Contains(countries, country.Country.IsoCode), nil
}

func (r *Router) matchAddrToGeoIPCountries(countries []string, addr netip.Addr) (bool, error) {
	return r.matchIPToGeoIPCountries(countries, addr.AsSlice())
}

func (r *Router) matchResultToGeoIPCountries(countries []string, result dns.Result) (bool, error) {
	for _, v6 := range result.IPv6 {
		return r.matchAddrToGeoIPCountries(countries, v6)
	}

	for _, v4 := range result.IPv4 {
		return r.matchAddrToGeoIPCountries(countries, v4)
	}

	return false, nil
}

func (r *Router) matchSocksAddrToGeoIPCountries(countries []string, addr socks5.Addr) (bool, error) {
	var ip net.IP

	switch addr[0] {
	case socks5.AtypIPv4:
		ip = net.IP(addr[1 : 1+net.IPv4len])
	case socks5.AtypIPv6:
		ip = net.IP(addr[1 : 1+net.IPv6len])
	default:
		return false, fmt.Errorf("unsupported address type: %d", addr[0])
	}

	return r.matchIPToGeoIPCountries(countries, ip)
}

func matchDomainToDomainSets(domainSets []DomainSet, domain string) bool {
	for _, ds := range domainSets {
		if ds.Match(domain) {
			return true
		}
	}
	return false
}

func matchAddrToPrefixes(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func matchResultToPrefixes(prefixes []netip.Prefix, result dns.Result) bool {
	for _, v4 := range result.IPv4 {
		if matchAddrToPrefixes(prefixes, v4) {
			return true
		}
	}

	for _, v6 := range result.IPv6 {
		if matchAddrToPrefixes(prefixes, v6) {
			return true
		}
	}

	return false
}

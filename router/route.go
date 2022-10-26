package router

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/slices"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
	"go4.org/netipx"
)

// ErrRejected is a special error that indicates the request is rejected.
var ErrRejected = errors.New("rejected")

// RouteConfig is a routing rule.
type RouteConfig struct {
	// Name of this route. Used in logs to identify matched routes.
	Name string `json:"name"`

	// Apply this route to "tcp" or "udp" only. If empty, match all requests.
	Network string `json:"network"`

	// Route matched requests to this client. Must not be empty.
	Client string `json:"client"`

	// When matching a domain target to IP prefixes, use this resolver to resolve the domain name.
	// If unspecified, use all resolvers by order.
	Resolver string `json:"resolver"`

	// Match requests from these servers. If empty, match all requests.
	FromServers []string `json:"fromServers"`

	// Match requests from IP addresses in these prefixes. If empty, match all requests.
	FromPrefixes []netip.Prefix `json:"fromPrefixes"`

	// Match requests from IP addresses in these prefix sets. If empty, match all requests.
	FromPrefixSets []string `json:"fromPrefixSets"`

	// Match requests from IP addresses in these countries. If empty, match all requests.
	FromGeoIPCountries []string `json:"fromGeoIPCountries"`

	// Match requests from these ports. If empty, match all requests.
	FromPorts []uint16 `json:"fromPorts"`

	// Match requests to these domain targets. If empty, match all requests.
	ToDomains []string `json:"toDomains"`

	// Match requests to domains in these domain sets. If empty, match all requests.
	ToDomainSets []string `json:"toDomainSets"`

	// Require the matched domain target to resolve to IP addresses in these prefixes.
	ToMatchedDomainExpectedPrefixes []netip.Prefix `json:"toMatchedDomainExpectedPrefixes"`

	// Require the matched domain target to resolve to IP addresses in these prefix sets.
	ToMatchedDomainExpectedPrefixSets []string `json:"toMatchedDomainExpectedPrefixSets"`

	// Require the matched domain target to resolve to IP addresses in these countries.
	ToMatchedDomainExpectedGeoIPCountries []string `json:"toMatchedDomainExpectedGeoIPCountries"`

	// Match requests to IP addresses in these prefixes. If empty, match all requests.
	ToPrefixes []netip.Prefix `json:"toPrefixes"`

	// Match requests to IP addresses in these prefix sets. If empty, match all requests.
	ToPrefixSets []string `json:"toPrefixSets"`

	// Match requests to IP addresses in these countries. If empty, match all requests.
	ToGeoIPCountries []string `json:"toGeoIPCountries"`

	// Match requests to these ports. If empty, match all requests.
	ToPorts []uint16 `json:"toPorts"`

	// Do not resolve destination domains to match IP rules.
	DisableNameResolutionForIPRules bool `json:"disableNameResolutionForIPRules"`

	// Invert source server matching logic. Match requests from all servers except those in FromServers.
	InvertFromServers bool `json:"invertFromServers"`

	// Invert source IP prefix matching logic. Match requests from all IP prefixes except those in FromPrefixes or FromPrefixSets.
	InvertFromPrefixes bool `json:"invertFromPrefixes"`

	// Invert source GeoIP country matching logic. Match requests from all countries except those in FromGeoIPCountries.
	InvertFromGeoIPCountries bool `json:"invertFromGeoIPCountries"`

	// Invert source port matching logic. Match requests from all ports except those in FromPorts.
	InvertFromPorts bool `json:"invertFromPorts"`

	// Invert destination domain matching logic. Match requests to all domains except those in ToDomains or ToDomainSets.
	InvertToDomains bool `json:"invertToDomains"`

	// Invert destination domain expected prefix matching logic. Match requests to all domains except those whose resolved IP addresses are in ToMatchedDomainExpectedPrefixes or ToMatchedDomainExpectedPrefixSets.
	InvertToMatchedDomainExpectedPrefixes bool `json:"invertToMatchedDomainExpectedPrefixes"`

	// Invert destination domain expected GeoIP country matching logic. Match requests to all domains except those whose resolved IP addresses are in ToMatchedDomainExpectedGeoIPCountries.
	InvertToMatchedDomainExpectedGeoIPCountries bool `json:"invertToMatchedDomainExpectedGeoIPCountries"`

	// Invert destination IP prefix matching logic. Match requests to all IP prefixes except those in ToPrefixes or ToPrefixSets.
	InvertToPrefixes bool `json:"invertToPrefixes"`

	// Invert destination GeoIP country matching logic. Match requests to all countries except those in ToGeoIPCountries.
	InvertToGeoIPCountries bool `json:"invertToGeoIPCountries"`

	// Invert destination port matching logic. Match requests to all ports except those in ToPorts.
	InvertToPorts bool `json:"invertToPorts"`
}

// Route creates a route from the RouteConfig.
func (rc *RouteConfig) Route(geoip *geoip2.Reader, logger *zap.Logger, resolvers []*dns.Resolver, resolverMap map[string]*dns.Resolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, domainSetMap map[string]domainset.DomainSet, prefixSetMap map[string]*netipx.IPSet) (Route, error) {
	// Bad name.
	switch rc.Name {
	case "", "default":
		return Route{}, errors.New("route name cannot be empty or 'default'")
	}

	// Has GeoIP criteria but no GeoIP database.
	if geoip == nil && (len(rc.FromGeoIPCountries) > 0 || len(rc.ToGeoIPCountries) > 0 || len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0) {
		return Route{}, errors.New("missing GeoLite2 country database path")
	}

	// Needs to resolve domain names but has no resolvers.
	if len(resolvers) == 0 &&
		(len(rc.ToMatchedDomainExpectedPrefixes) > 0 ||
			len(rc.ToMatchedDomainExpectedPrefixSets) > 0 ||
			len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0 ||
			!rc.DisableNameResolutionForIPRules &&
				(len(rc.ToPrefixes) > 0 || len(rc.ToPrefixSets) > 0 || len(rc.ToGeoIPCountries) > 0)) {
		return Route{}, errors.New("missing resolvers")
	}

	// Has resolved IP expectations but no destination domain criteria.
	if len(rc.ToDomains) == 0 && len(rc.ToDomainSets) == 0 &&
		(len(rc.ToMatchedDomainExpectedPrefixes) > 0 ||
			len(rc.ToMatchedDomainExpectedPrefixSets) > 0 ||
			len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0) {
		return Route{}, errors.New("missing destination domain criteria")
	}

	if rc.Resolver != "" {
		resolver, ok := resolverMap[rc.Resolver]
		if !ok {
			return Route{}, fmt.Errorf("resolver not found: %s", rc.Resolver)
		}
		resolvers = []*dns.Resolver{resolver}
	}

	route := Route{name: rc.Name}

	switch rc.Network {
	case "":
	case "tcp":
		route.AddCriterion(NetworkTCPCriterion{}, false)
	case "udp":
		route.AddCriterion(NetworkUDPCriterion{}, false)
	default:
		return Route{}, fmt.Errorf("invalid network: %s", rc.Network)
	}

	if rc.Client != "reject" {
		switch rc.Network {
		case "", "tcp":
			route.tcpClient = tcpClientMap[rc.Client]
			if route.tcpClient == nil {
				return Route{}, fmt.Errorf("TCP client not found: %s", rc.Client)
			}
		}

		switch rc.Network {
		case "", "udp":
			route.udpClient = udpClientMap[rc.Client]
			if route.udpClient == nil {
				return Route{}, fmt.Errorf("UDP client not found: %s", rc.Client)
			}
		}
	}

	if len(rc.FromServers) > 0 {
		route.AddCriterion((*SourceServerCriterion)(&rc.FromServers), rc.InvertFromServers)
	}

	if len(rc.FromPrefixes) > 0 || len(rc.FromPrefixSets) > 0 || len(rc.FromGeoIPCountries) > 0 {
		var group CriterionGroupOR

		if len(rc.FromPrefixes) > 0 || len(rc.FromPrefixSets) > 0 {
			var sb netipx.IPSetBuilder

			for _, prefix := range rc.FromPrefixes {
				sb.AddPrefix(prefix)
			}

			for _, prefixSet := range rc.FromPrefixSets {
				s, ok := prefixSetMap[prefixSet]
				if !ok {
					return Route{}, fmt.Errorf("prefix set not found: %s", prefixSet)
				}
				sb.AddSet(s)
			}

			sourceIPSet, err := sb.IPSet()
			if err != nil {
				return Route{}, fmt.Errorf("failed to build sourceIPSet: %w", err)
			}

			group.AddCriterion((*SourceIPCriterion)(sourceIPSet), rc.InvertFromPrefixes)
		}

		if len(rc.FromGeoIPCountries) > 0 {
			group.AddCriterion(&SourceGeoIPCountryCriterion{
				countries: rc.FromGeoIPCountries,
				geoip:     geoip,
				logger:    logger,
			}, rc.InvertFromGeoIPCountries)
		}

		route.criteria = group.AppendTo(route.criteria)
	}

	if len(rc.FromPorts) > 0 {
		route.AddCriterion((*SourcePortCriterion)(&rc.FromPorts), rc.InvertFromPorts)
	}

	if len(rc.ToDomains) > 0 || len(rc.ToDomainSets) > 0 || len(rc.ToPrefixes) > 0 || len(rc.ToPrefixSets) > 0 || len(rc.ToGeoIPCountries) > 0 {
		var group CriterionGroupOR

		if len(rc.ToDomains) > 0 || len(rc.ToDomainSets) > 0 {
			var defaultDomainSetCount int

			if len(rc.ToDomains) > 0 {
				defaultDomainSetCount = 1
			}

			domainSets := make([]domainset.DomainSet, defaultDomainSetCount+len(rc.ToDomainSets))

			if defaultDomainSetCount == 1 {
				mb := domainset.DomainLinearMatcher(rc.ToDomains)
				ds, err := mb.AppendTo(nil)
				if err != nil {
					return Route{}, err
				}
				domainSets[0] = ds
			}

			for i, tds := range rc.ToDomainSets {
				ds, ok := domainSetMap[tds]
				if !ok {
					return Route{}, fmt.Errorf("domain set not found: %s", tds)
				}
				domainSets[defaultDomainSetCount+i] = ds
			}

			if len(rc.ToMatchedDomainExpectedPrefixes) > 0 || len(rc.ToMatchedDomainExpectedPrefixSets) > 0 || len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0 {
				var expectedIPCriterionGroup CriterionGroupOR

				if len(rc.ToMatchedDomainExpectedPrefixes) > 0 || len(rc.ToMatchedDomainExpectedPrefixSets) > 0 {
					var sb netipx.IPSetBuilder

					for _, prefix := range rc.ToMatchedDomainExpectedPrefixes {
						sb.AddPrefix(prefix)
					}

					for _, prefixSet := range rc.ToMatchedDomainExpectedPrefixSets {
						s, ok := prefixSetMap[prefixSet]
						if !ok {
							return Route{}, fmt.Errorf("prefix set not found: %s", prefixSet)
						}
						sb.AddSet(s)
					}

					expectedIPSet, err := sb.IPSet()
					if err != nil {
						return Route{}, fmt.Errorf("failed to build expectedIPSet: %w", err)
					}

					expectedIPCriterionGroup.AddCriterion(&DestResolvedIPCriterion{expectedIPSet, resolvers}, rc.InvertToMatchedDomainExpectedPrefixes)
				}

				if len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0 {
					expectedIPCriterionGroup.AddCriterion(&DestResolvedGeoIPCountryCriterion{
						countries: rc.ToMatchedDomainExpectedGeoIPCountries,
						geoip:     geoip,
						logger:    logger,
						resolvers: resolvers,
					}, rc.InvertToMatchedDomainExpectedGeoIPCountries)
				}

				group.AddCriterion(&DestDomainExpectedIPCriterion{domainSets, expectedIPCriterionGroup.Criterion()}, rc.InvertToDomains)
			} else {
				group.AddCriterion((*DestDomainCriterion)(&domainSets), rc.InvertToDomains)
			}
		}

		if len(rc.ToPrefixes) > 0 || len(rc.ToPrefixSets) > 0 {
			var sb netipx.IPSetBuilder

			for _, prefix := range rc.ToPrefixes {
				sb.AddPrefix(prefix)
			}

			for _, prefixSet := range rc.ToPrefixSets {
				s, ok := prefixSetMap[prefixSet]
				if !ok {
					return Route{}, fmt.Errorf("prefix set not found: %s", prefixSet)
				}
				sb.AddSet(s)
			}

			destIPSet, err := sb.IPSet()
			if err != nil {
				return Route{}, fmt.Errorf("failed to build destIPSet: %w", err)
			}

			if rc.DisableNameResolutionForIPRules {
				group.AddCriterion((*DestIPCriterion)(destIPSet), rc.InvertToPrefixes)
			} else {
				group.AddCriterion(&DestResolvedIPCriterion{destIPSet, resolvers}, rc.InvertToPrefixes)
			}
		}

		if len(rc.ToGeoIPCountries) > 0 {
			if rc.DisableNameResolutionForIPRules {
				group.AddCriterion(&DestGeoIPCountryCriterion{
					countries: rc.ToGeoIPCountries,
					geoip:     geoip,
					logger:    logger,
				}, rc.InvertToGeoIPCountries)
			} else {
				group.AddCriterion(&DestResolvedGeoIPCountryCriterion{
					countries: rc.ToGeoIPCountries,
					geoip:     geoip,
					logger:    logger,
					resolvers: resolvers,
				}, rc.InvertToGeoIPCountries)
			}
		}

		route.criteria = group.AppendTo(route.criteria)
	}

	if len(rc.ToPorts) > 0 {
		route.AddCriterion((*DestPortCriterion)(&rc.ToPorts), rc.InvertToPorts)
	}

	return route, nil
}

// Route controls which client a request is routed to.
type Route struct {
	name      string
	criteria  []Criterion
	tcpClient zerocopy.TCPClient
	udpClient zerocopy.UDPClient
}

// String returns the name of the route.
func (r *Route) String() string {
	return r.name
}

// AddCriterion adds a criterion to the route.
func (r *Route) AddCriterion(criterion Criterion, invert bool) {
	if invert {
		criterion = &InvertedCriterion{Inner: criterion}
	}
	r.criteria = append(r.criteria, criterion)
}

// Match returns whether the request matches the route.
func (r *Route) Match(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	for _, criterion := range r.criteria {
		met, err := criterion.Meet(network, server, sourceAddrPort, targetAddr)
		if !met {
			return false, err
		}
	}
	return true, nil
}

// TCPClient returns the TCP client to use for the request.
func (r *Route) TCPClient() (zerocopy.TCPClient, error) {
	if r.tcpClient == nil {
		return nil, ErrRejected
	}
	return r.tcpClient, nil
}

// UDPClient returns the UDP client to use for the request.
func (r *Route) UDPClient() (zerocopy.UDPClient, error) {
	if r.udpClient == nil {
		return nil, ErrRejected
	}
	return r.udpClient, nil
}

// Criterion is used by [Route] to determine whether a request matches the route.
type Criterion interface {
	// Meet returns whether the request meets the criterion.
	Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error)
}

// InvertedCriterion is like the inner criterion, but inverted.
type InvertedCriterion struct {
	Inner Criterion
}

// Meet implements the Criterion Meet method.
func (c InvertedCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	met, err := c.Inner.Meet(network, server, sourceAddrPort, targetAddr)
	if err != nil {
		return false, err
	}
	return !met, nil
}

// CriterionGroupOR groups multiple criteria together with OR logic.
type CriterionGroupOR struct {
	Criteria []Criterion
}

// AddCriterion adds a criterion to the group.
func (g *CriterionGroupOR) AddCriterion(criterion Criterion, invert bool) {
	if invert {
		criterion = &InvertedCriterion{Inner: criterion}
	}
	g.Criteria = append(g.Criteria, criterion)
}

// Meet returns whether the request meets any of the criteria.
func (g *CriterionGroupOR) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	for _, criterion := range g.Criteria {
		met, err := criterion.Meet(network, server, sourceAddrPort, targetAddr)
		if err != nil {
			return false, err
		}
		if met {
			return true, nil
		}
	}
	return false, nil
}

// Criterion returns a single criterion that represents the group, or nil if the group is empty.
func (g *CriterionGroupOR) Criterion() Criterion {
	switch len(g.Criteria) {
	case 0:
		return nil
	case 1:
		return g.Criteria[0]
	default:
		return g
	}
}

// AppendTo appends the group to the criterion slice.
// When there are more than one criterion in the group, the group itself is appended.
// When there is only one criterion in the group, the criterion is appended directly.
// When there are no criteria in the group, the criterion slice is returned unchanged.
func (g *CriterionGroupOR) AppendTo(criteria []Criterion) []Criterion {
	switch len(g.Criteria) {
	case 0:
		return criteria
	case 1:
		return append(criteria, g.Criteria[0])
	default:
		return append(criteria, g)
	}
}

type protocol byte

const (
	protocolTCP protocol = iota
	protocolUDP
)

// NetworkTCPCriterion restricts the network to TCP.
type NetworkTCPCriterion struct{}

// Meet implements the Criterion Meet method.
func (NetworkTCPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return network == protocolTCP, nil
}

// NetworkUDPCriterion restricts the network to UDP.
type NetworkUDPCriterion struct{}

// Meet implements the Criterion Meet method.
func (NetworkUDPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return network == protocolUDP, nil
}

// SourceServerCriterion restricts the source server.
type SourceServerCriterion []string

// Meet implements the Criterion Meet method.
func (c SourceServerCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return slices.Contains(c, server), nil
}

// SourceIPCriterion restricts the source IP address.
type SourceIPCriterion netipx.IPSet

// Meet implements the Criterion Meet method.
func (c *SourceIPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return (*netipx.IPSet)(c).Contains(sourceAddrPort.Addr().Unmap()), nil
}

// SourceGeoIPCountryCriterion restricts the source IP address by GeoIP country.
type SourceGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
}

// Meet implements the Criterion Meet method.
func (c SourceGeoIPCountryCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return matchAddrToGeoIPCountries(c.countries, sourceAddrPort.Addr(), c.geoip, c.logger)
}

// SourcePortCriterion restricts the source port.
type SourcePortCriterion []uint16

// Meet implements the Criterion Meet method.
func (c SourcePortCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return slices.Contains(c, sourceAddrPort.Port()), nil
}

// DestDomainCriterion restricts the destination domain.
type DestDomainCriterion []domainset.DomainSet

// Meet implements the Criterion Meet method.
func (c DestDomainCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	if targetAddr.IsIP() {
		return false, nil
	}
	return matchDomainToDomainSets(c, targetAddr.Domain()), nil
}

// DestDomainExpectedIPCriterion restricts the destination domain and its resolved IP address.
type DestDomainExpectedIPCriterion struct {
	destDomainCriterion DestDomainCriterion
	expectedIPCriterion Criterion
}

// Meet implements the Criterion Meet method.
func (c *DestDomainExpectedIPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	met, err := c.destDomainCriterion.Meet(network, server, sourceAddrPort, targetAddr)
	if !met {
		return false, err
	}
	return c.expectedIPCriterion.Meet(network, server, sourceAddrPort, targetAddr)
}

// DestIPCriterion restricts the destination IP address.
type DestIPCriterion netipx.IPSet

// Meet implements the Criterion Meet method.
func (c *DestIPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	if !targetAddr.IsIP() {
		return false, nil
	}
	return (*netipx.IPSet)(c).Contains(targetAddr.IP().Unmap()), nil
}

// DestResolvedIPCriterion restricts the destination IP address or the destination domain's resolved IP address.
type DestResolvedIPCriterion struct {
	ipSet     *netipx.IPSet
	resolvers []*dns.Resolver
}

// Meet implements the Criterion Meet method.
func (c *DestResolvedIPCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	if targetAddr.IsIP() {
		return c.ipSet.Contains(targetAddr.IP().Unmap()), nil
	}
	return matchDomainToIPSet(c.resolvers, targetAddr.Domain(), c.ipSet)
}

// DestGeoIPCountryCriterion restricts the destination IP address by GeoIP country.
type DestGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
}

// Meet implements the Criterion Meet method.
func (c *DestGeoIPCountryCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	if !targetAddr.IsIP() {
		return false, nil
	}
	return matchAddrToGeoIPCountries(c.countries, targetAddr.IP(), c.geoip, c.logger)
}

// DestResolvedGeoIPCountryCriterion restricts the destination IP address or the destination domain's resolved IP address by GeoIP country.
type DestResolvedGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
	resolvers []*dns.Resolver
}

// Meet implements the Criterion Meet method.
func (c *DestResolvedGeoIPCountryCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	if targetAddr.IsIP() {
		return matchAddrToGeoIPCountries(c.countries, targetAddr.IP(), c.geoip, c.logger)
	}
	return matchDomainToGeoIPCountries(c.resolvers, targetAddr.Domain(), c.countries, c.geoip, c.logger)
}

// DestPortCriterion restricts the destination port.
type DestPortCriterion []uint16

// Meet implements the Criterion Meet method.
func (c DestPortCriterion) Meet(network protocol, server string, sourceAddrPort netip.AddrPort, targetAddr conn.Addr) (bool, error) {
	return slices.Contains(c, targetAddr.Port()), nil
}

func matchAddrToGeoIPCountries(countries []string, addr netip.Addr, geoip *geoip2.Reader, logger *zap.Logger) (bool, error) {
	country, err := geoip.Country(addr.AsSlice())
	if err != nil {
		return false, err
	}
	if ce := logger.Check(zap.DebugLevel, "Matched GeoIP country"); ce != nil {
		ce.Write(
			zap.Stringer("ip", addr),
			zap.String("country", country.Country.IsoCode),
		)
	}
	return slices.Contains(countries, country.Country.IsoCode), nil
}

func matchResultToGeoIPCountries(countries []string, result dns.Result, geoip *geoip2.Reader, logger *zap.Logger) (bool, error) {
	for _, v6 := range result.IPv6 {
		return matchAddrToGeoIPCountries(countries, v6, geoip, logger)
	}
	for _, v4 := range result.IPv4 {
		return matchAddrToGeoIPCountries(countries, v4, geoip, logger)
	}
	return false, nil
}

func matchResultToIPSet(ipSet *netipx.IPSet, result dns.Result) bool {
	for _, v6 := range result.IPv6 {
		return ipSet.Contains(v6)
	}
	for _, v4 := range result.IPv4 {
		return ipSet.Contains(v4)
	}
	return false
}

func lookup(resolvers []*dns.Resolver, domain string) (result dns.Result, err error) {
	for _, resolver := range resolvers {
		result, err = resolver.Lookup(domain)
		if err == dns.ErrLookup {
			continue
		}
		return
	}
	return result, dns.ErrLookup
}

func matchDomainToDomainSets(domainSets []domainset.DomainSet, domain string) bool {
	for _, ds := range domainSets {
		if ds.Match(domain) {
			return true
		}
	}
	return false
}

func matchDomainToGeoIPCountries(resolvers []*dns.Resolver, domain string, countries []string, geoip *geoip2.Reader, logger *zap.Logger) (bool, error) {
	result, err := lookup(resolvers, domain)
	if err != nil {
		return false, err
	}
	return matchResultToGeoIPCountries(countries, result, geoip, logger)
}

func matchDomainToIPSet(resolvers []*dns.Resolver, domain string, ipSet *netipx.IPSet) (bool, error) {
	result, err := lookup(resolvers, domain)
	if err != nil {
		return false, err
	}
	return matchResultToIPSet(ipSet, result), nil
}

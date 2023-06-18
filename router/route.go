package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/bitset"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/portset"
	"github.com/database64128/shadowsocks-go/slices"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
	"go4.org/netipx"
)

// ErrRejected is a special error that indicates the request is rejected.
var ErrRejected = errors.New("rejected")

var errPointlessPortCriteria = errors.New("matching all ports is equivalent to not having any port filtering rules")

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

	// Match requests from these users. If empty, match all requests.
	FromUsers []string `json:"fromUsers"`

	// Match requests from these ports. If empty, match all requests.
	FromPorts []uint16 `json:"fromPorts"`

	// Match requests from these ports and port ranges. If empty, match all requests.
	FromPortRanges string `json:"fromPortRanges"`

	// Match requests from IP addresses in these prefixes. If empty, match all requests.
	FromPrefixes []netip.Prefix `json:"fromPrefixes"`

	// Match requests from IP addresses in these prefix sets. If empty, match all requests.
	FromPrefixSets []string `json:"fromPrefixSets"`

	// Match requests from IP addresses in these countries. If empty, match all requests.
	FromGeoIPCountries []string `json:"fromGeoIPCountries"`

	// Match requests to these ports. If empty, match all requests.
	ToPorts []uint16 `json:"toPorts"`

	// Match requests to these ports and port ranges. If empty, match all requests.
	ToPortRanges string `json:"toPortRanges"`

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

	// Do not resolve destination domains to match IP rules.
	DisableNameResolutionForIPRules bool `json:"disableNameResolutionForIPRules"`

	// Invert source server matching logic. Match requests from all servers except those in FromServers.
	InvertFromServers bool `json:"invertFromServers"`

	// Invert source user matching logic. Match requests from all users except those in FromUsers.
	InvertFromUsers bool `json:"invertFromUsers"`

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
func (rc *RouteConfig) Route(geoip *geoip2.Reader, logger *zap.Logger, resolvers []dns.SimpleResolver, resolverMap map[string]dns.SimpleResolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, serverIndexByName map[string]int, domainSetMap map[string]domainset.DomainSet, prefixSetMap map[string]*netipx.IPSet) (Route, error) {
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
		resolvers = []dns.SimpleResolver{resolver}
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
		sourceServerSet := bitset.NewBitSet(uint(len(serverIndexByName)))

		for _, server := range rc.FromServers {
			index, ok := serverIndexByName[server]
			if !ok {
				return Route{}, fmt.Errorf("server not found: %s", server)
			}
			sourceServerSet.Set(uint(index))
		}

		route.AddCriterion(SourceServerCriterion(sourceServerSet), rc.InvertFromServers)
	}

	if len(rc.FromUsers) > 0 {
		route.AddCriterion(SourceUserCriterion(rc.FromUsers), rc.InvertFromUsers)
	}

	if len(rc.FromPorts) > 0 || rc.FromPortRanges != "" {
		var portSet portset.PortSet

		for _, port := range rc.FromPorts {
			if port == 0 {
				return Route{}, fmt.Errorf("bad fromPorts: %w", portset.ErrZeroPort)
			}
			portSet.Add(port)
		}

		if err := portSet.Parse(rc.FromPortRanges); err != nil {
			return Route{}, fmt.Errorf("failed to parse source port ranges: %w", err)
		}

		portCount := portSet.Count()
		switch portCount {
		case 0:
			panic("unreachable")
		case 1:
			route.AddCriterion(SourcePortCriterion(portSet.First()), rc.InvertFromPorts)
		case 65535:
			return Route{}, fmt.Errorf("bad source port criteria: %w", errPointlessPortCriteria)
		default:
			portRangeCount := portSet.RangeCount()
			if portRangeCount <= 16 {
				route.AddCriterion(SourcePortRangeSetCriterion(portSet.RangeSet()), rc.InvertFromPorts)
			} else {
				sourcePortSetCriterion := SourcePortSetCriterion(portSet)
				route.AddCriterion(&sourcePortSetCriterion, rc.InvertFromPorts)
			}
		}
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
			group.AddCriterion(SourceGeoIPCountryCriterion{
				countries: rc.FromGeoIPCountries,
				geoip:     geoip,
				logger:    logger,
			}, rc.InvertFromGeoIPCountries)
		}

		route.criteria = group.AppendTo(route.criteria)
	}

	if len(rc.ToPorts) > 0 || rc.ToPortRanges != "" {
		var portSet portset.PortSet

		for _, port := range rc.ToPorts {
			if port == 0 {
				return Route{}, fmt.Errorf("bad toPorts: %w", portset.ErrZeroPort)
			}
			portSet.Add(port)
		}

		if err := portSet.Parse(rc.ToPortRanges); err != nil {
			return Route{}, fmt.Errorf("failed to parse destination port ranges: %w", err)
		}

		portCount := portSet.Count()
		switch portCount {
		case 0:
			panic("unreachable")
		case 1:
			route.AddCriterion(DestPortCriterion(portSet.First()), rc.InvertToPorts)
		case 65535:
			return Route{}, fmt.Errorf("bad destination port criteria: %w", errPointlessPortCriteria)
		default:
			portRangeCount := portSet.RangeCount()
			if portRangeCount <= 16 {
				route.AddCriterion(DestPortRangeSetCriterion(portSet.RangeSet()), rc.InvertToPorts)
			} else {
				destPortSetCriterion := DestPortSetCriterion(portSet)
				route.AddCriterion(&destPortSetCriterion, rc.InvertToPorts)
			}
		}
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

					expectedIPCriterionGroup.AddCriterion(DestResolvedIPCriterion{expectedIPSet, resolvers}, rc.InvertToMatchedDomainExpectedPrefixes)
				}

				if len(rc.ToMatchedDomainExpectedGeoIPCountries) > 0 {
					expectedIPCriterionGroup.AddCriterion(DestResolvedGeoIPCountryCriterion{
						countries: rc.ToMatchedDomainExpectedGeoIPCountries,
						geoip:     geoip,
						logger:    logger,
						resolvers: resolvers,
					}, rc.InvertToMatchedDomainExpectedGeoIPCountries)
				}

				group.AddCriterion(DestDomainExpectedIPCriterion{domainSets, expectedIPCriterionGroup.Criterion()}, rc.InvertToDomains)
			} else {
				group.AddCriterion(DestDomainCriterion(domainSets), rc.InvertToDomains)
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
				group.AddCriterion(DestResolvedIPCriterion{destIPSet, resolvers}, rc.InvertToPrefixes)
			}
		}

		if len(rc.ToGeoIPCountries) > 0 {
			if rc.DisableNameResolutionForIPRules {
				group.AddCriterion(DestGeoIPCountryCriterion{
					countries: rc.ToGeoIPCountries,
					geoip:     geoip,
					logger:    logger,
				}, rc.InvertToGeoIPCountries)
			} else {
				group.AddCriterion(DestResolvedGeoIPCountryCriterion{
					countries: rc.ToGeoIPCountries,
					geoip:     geoip,
					logger:    logger,
					resolvers: resolvers,
				}, rc.InvertToGeoIPCountries)
			}
		}

		route.criteria = group.AppendTo(route.criteria)
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
		criterion = InvertedCriterion{Inner: criterion}
	}
	r.criteria = append(r.criteria, criterion)
}

// Match returns whether the request matches the route.
func (r *Route) Match(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	for _, criterion := range r.criteria {
		met, err := criterion.Meet(ctx, network, requestInfo)
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
	Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error)
}

// InvertedCriterion is like the inner criterion, but inverted.
type InvertedCriterion struct {
	Inner Criterion
}

// Meet implements the Criterion Meet method.
func (c InvertedCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	met, err := c.Inner.Meet(ctx, network, requestInfo)
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
		criterion = InvertedCriterion{Inner: criterion}
	}
	g.Criteria = append(g.Criteria, criterion)
}

// Meet returns whether the request meets any of the criteria.
func (g CriterionGroupOR) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	for _, criterion := range g.Criteria {
		met, err := criterion.Meet(ctx, network, requestInfo)
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
func (g CriterionGroupOR) Criterion() Criterion {
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
func (g CriterionGroupOR) AppendTo(criteria []Criterion) []Criterion {
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

// RequestInfo contains information about a request that can be met by one or more criteria.
type RequestInfo struct {
	ServerIndex    int
	Username       string
	SourceAddrPort netip.AddrPort
	TargetAddr     conn.Addr
}

// NetworkTCPCriterion restricts the network to TCP.
type NetworkTCPCriterion struct{}

// Meet implements the Criterion Meet method.
func (NetworkTCPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return network == protocolTCP, nil
}

// NetworkUDPCriterion restricts the network to UDP.
type NetworkUDPCriterion struct{}

// Meet implements the Criterion Meet method.
func (NetworkUDPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return network == protocolUDP, nil
}

// SourceServerCriterion restricts the source server.
type SourceServerCriterion bitset.BitSet

// Meet implements the Criterion Meet method.
func (c SourceServerCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return bitset.BitSet(c).IsSet(uint(requestInfo.ServerIndex)), nil
}

// SourceUserCriterion restricts the source user.
type SourceUserCriterion []string

// Meet implements the Criterion Meet method.
func (c SourceUserCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return slices.Contains(c, requestInfo.Username), nil
}

// SourcePortCriterion restricts the source port.
type SourcePortCriterion uint16

// Meet implements the Criterion Meet method.
func (c SourcePortCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return uint16(c) == requestInfo.SourceAddrPort.Port(), nil
}

// SourcePortRangeSetCriterion restricts the source port to ports in a port range set.
type SourcePortRangeSetCriterion portset.PortRangeSet

// Meet implements the Criterion Meet method.
func (c SourcePortRangeSetCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return portset.PortRangeSet(c).Contains(requestInfo.SourceAddrPort.Port()), nil
}

// SourcePortSetCriterion restricts the source port to ports in a port set.
type SourcePortSetCriterion portset.PortSet

// Meet implements the Criterion Meet method.
func (c *SourcePortSetCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return (*portset.PortSet)(c).Contains(requestInfo.SourceAddrPort.Port()), nil
}

// SourceIPCriterion restricts the source IP address.
type SourceIPCriterion netipx.IPSet

// Meet implements the Criterion Meet method.
func (c *SourceIPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return (*netipx.IPSet)(c).Contains(requestInfo.SourceAddrPort.Addr().Unmap()), nil
}

// SourceGeoIPCountryCriterion restricts the source IP address by GeoIP country.
type SourceGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
}

// Meet implements the Criterion Meet method.
func (c SourceGeoIPCountryCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return matchAddrToGeoIPCountries(c.countries, requestInfo.SourceAddrPort.Addr(), c.geoip, c.logger)
}

// DestPortCriterion restricts the destination port.
type DestPortCriterion uint16

// Meet implements the Criterion Meet method.
func (c DestPortCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return uint16(c) == requestInfo.TargetAddr.Port(), nil
}

// DestPortRangeSetCriterion restricts the destination port to ports in a port range set.
type DestPortRangeSetCriterion portset.PortRangeSet

// Meet implements the Criterion Meet method.
func (c DestPortRangeSetCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return portset.PortRangeSet(c).Contains(requestInfo.TargetAddr.Port()), nil
}

// DestPortSetCriterion restricts the destination port to ports in a port set.
type DestPortSetCriterion portset.PortSet

// Meet implements the Criterion Meet method.
func (c *DestPortSetCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	return (*portset.PortSet)(c).Contains(requestInfo.TargetAddr.Port()), nil
}

// DestDomainCriterion restricts the destination domain.
type DestDomainCriterion []domainset.DomainSet

// Meet implements the Criterion Meet method.
func (c DestDomainCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	if requestInfo.TargetAddr.IsIP() {
		return false, nil
	}
	return matchDomainToDomainSets(c, requestInfo.TargetAddr.Domain()), nil
}

// DestDomainExpectedIPCriterion restricts the destination domain and its resolved IP address.
type DestDomainExpectedIPCriterion struct {
	destDomainCriterion DestDomainCriterion
	expectedIPCriterion Criterion
}

// Meet implements the Criterion Meet method.
func (c DestDomainExpectedIPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	met, err := c.destDomainCriterion.Meet(ctx, network, requestInfo)
	if !met {
		return false, err
	}
	return c.expectedIPCriterion.Meet(ctx, network, requestInfo)
}

// DestIPCriterion restricts the destination IP address.
type DestIPCriterion netipx.IPSet

// Meet implements the Criterion Meet method.
func (c *DestIPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	if !requestInfo.TargetAddr.IsIP() {
		return false, nil
	}
	return (*netipx.IPSet)(c).Contains(requestInfo.TargetAddr.IP().Unmap()), nil
}

// DestResolvedIPCriterion restricts the destination IP address or the destination domain's resolved IP address.
type DestResolvedIPCriterion struct {
	ipSet     *netipx.IPSet
	resolvers []dns.SimpleResolver
}

// Meet implements the Criterion Meet method.
func (c DestResolvedIPCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	if requestInfo.TargetAddr.IsIP() {
		return c.ipSet.Contains(requestInfo.TargetAddr.IP().Unmap()), nil
	}
	return matchDomainToIPSet(ctx, c.resolvers, requestInfo.TargetAddr.Domain(), c.ipSet)
}

// DestGeoIPCountryCriterion restricts the destination IP address by GeoIP country.
type DestGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
}

// Meet implements the Criterion Meet method.
func (c DestGeoIPCountryCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	if !requestInfo.TargetAddr.IsIP() {
		return false, nil
	}
	return matchAddrToGeoIPCountries(c.countries, requestInfo.TargetAddr.IP(), c.geoip, c.logger)
}

// DestResolvedGeoIPCountryCriterion restricts the destination IP address or the destination domain's resolved IP address by GeoIP country.
type DestResolvedGeoIPCountryCriterion struct {
	countries []string
	geoip     *geoip2.Reader
	logger    *zap.Logger
	resolvers []dns.SimpleResolver
}

// Meet implements the Criterion Meet method.
func (c DestResolvedGeoIPCountryCriterion) Meet(ctx context.Context, network protocol, requestInfo RequestInfo) (bool, error) {
	if requestInfo.TargetAddr.IsIP() {
		return matchAddrToGeoIPCountries(c.countries, requestInfo.TargetAddr.IP(), c.geoip, c.logger)
	}
	return matchDomainToGeoIPCountries(ctx, c.resolvers, requestInfo.TargetAddr.Domain(), c.countries, c.geoip, c.logger)
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

func lookup(ctx context.Context, resolvers []dns.SimpleResolver, domain string) (ip netip.Addr, err error) {
	for _, resolver := range resolvers {
		ip, err = resolver.LookupIP(ctx, domain)
		if err == dns.ErrLookup {
			continue
		}
		return
	}
	return ip, dns.ErrLookup
}

func matchDomainToDomainSets(domainSets []domainset.DomainSet, domain string) bool {
	for _, ds := range domainSets {
		if ds.Match(domain) {
			return true
		}
	}
	return false
}

func matchDomainToGeoIPCountries(ctx context.Context, resolvers []dns.SimpleResolver, domain string, countries []string, geoip *geoip2.Reader, logger *zap.Logger) (bool, error) {
	ip, err := lookup(ctx, resolvers, domain)
	if err != nil {
		return false, err
	}
	return matchAddrToGeoIPCountries(countries, ip, geoip, logger)
}

func matchDomainToIPSet(ctx context.Context, resolvers []dns.SimpleResolver, domain string, ipSet *netipx.IPSet) (bool, error) {
	ip, err := lookup(ctx, resolvers, domain)
	if err != nil {
		return false, err
	}
	return ipSet.Contains(ip.Unmap()), nil
}

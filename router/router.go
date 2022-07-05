package router

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

var ErrRejected = errors.New("rejected")

// RouterConfig is the configuration for a Router.
type RouterConfig struct {
	DisableNameResolutionForIPRules bool    `json:"disableNameResolutionForIPRules"`
	DefaultTCPClientName            string  `json:"defaultTCPClientName"`
	DefaultUDPClientName            string  `json:"defaultUDPClientName"`
	Routes                          []Route `json:"routes"`
}

// Route is a routing rule.
type Route struct {
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

	// Match requests to these IP prefixes. If empty, match all requests.
	Prefixes []netip.Prefix `json:"prefixes"`

	// Match requests from these IP prefixes. If empty, match all requests.
	SourcePrefixes []netip.Prefix `json:"sourcePrefixes"`

	// Match requests to these ports. If empty, match all requests.
	Ports []uint16 `json:"ports"`

	// Match requests from these ports. If empty, match all requests.
	SourcePorts []uint16 `json:"sourcePorts"`

	// Invert domain matching logic. Match requests to all domains except those in Domains.
	InvertDomains bool `json:"invertDomains"`

	// Invert IP prefix matching logic. Match requests to all IP prefixes except those in Prefixes.
	InvertPrefixes bool `json:"invertPrefixes"`

	// Invert port matching logic. Match requests to all ports except those in Ports.
	InvertPorts bool `json:"invertPorts"`

	// Invert source IP prefix matching logic. Match requests from all IP prefixes except those in SourcePrefixes.
	InvertSourcePrefixes bool `json:"invertSourcePrefixes"`

	// Invert source port matching logic. Match requests from all ports except those in SourcePorts.
	InvertSourcePorts bool `json:"invertSourcePorts"`
}

// Router looks up the destination client for requests received by servers.
type Router struct {
	logger        *zap.Logger
	config        RouterConfig
	resolverNames []string
	resolverMap   map[string]*dns.Resolver
	tcpClientMap  map[string]zerocopy.TCPClient
	udpClientMap  map[string]zerocopy.UDPClient
}

// GetTCPClient returns the zerocopy.TCPClient for a TCP request received by serverName
// from sourceAddrPort to targetAddr.
func (r *Router) GetTCPClient(serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (zerocopy.TCPClient, error) {
	clientName, err := r.getClientName("tcp", serverName, sourceAddrPort, targetAddr)
	if err != nil {
		return nil, err
	}
	if clientName == "reject" {
		return nil, ErrRejected
	}

	client, ok := r.tcpClientMap[clientName]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientName)
	}
	return client, nil
}

// GetUDPClient returns the zerocopy.UDPClient for a UDP session received by serverName.
// The first received packet of the session is from sourceAddrPort to targetAddr.
func (r *Router) GetUDPClient(serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (zerocopy.UDPClient, error) {
	clientName, err := r.getClientName("udp", serverName, sourceAddrPort, targetAddr)
	if err != nil {
		return nil, err
	}
	if clientName == "reject" {
		return nil, ErrRejected
	}

	client, ok := r.udpClientMap[clientName]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientName)
	}
	return client, nil
}

func (r *Router) getClientName(network, serverName string, sourceAddrPort netip.AddrPort, targetAddr socks5.Addr) (string, error) {
	for _, route := range r.config.Routes {
		// Network
		switch route.Network {
		case "", network:
		default:
			continue
		}

		// ServerNames
		if len(route.ServerNames) > 0 && !slices.Contains(route.ServerNames, serverName) {
			continue
		}

		// SourcePorts
		if len(route.SourcePorts) > 0 && !slices.Contains(route.SourcePorts, sourceAddrPort.Port()) != route.InvertSourcePorts {
			continue
		}

		// SourcePrefixes
		if len(route.SourcePrefixes) > 0 && !matchAddrToPrefixes(route.SourcePrefixes, sourceAddrPort.Addr()) != route.InvertSourcePrefixes {
			continue
		}

		// Ports
		if len(route.Ports) > 0 && !slices.Contains(route.Ports, targetAddr.Port()) != route.InvertPorts {
			continue
		}

		// Domains
		if len(route.Domains) > 0 && targetAddr.IsDomain() && !slices.Contains(route.Domains, targetAddr.Host()) != route.InvertDomains {
			continue
		}

		// Prefixes
		if len(route.Prefixes) > 0 {
			if targetAddr.IsDomain() {
				if r.config.DisableNameResolutionForIPRules {
					continue
				}

				result, err := r.lookup(targetAddr.Host(), route.ResolverName)
				if err != nil {
					return "", err
				}

				if !matchResultToPrefixes(route.Prefixes, result) != route.InvertPrefixes {
					continue
				}
			} else {
				addr, err := targetAddr.Addr(true)
				if err != nil {
					return "", err
				}

				if !matchAddrToPrefixes(route.Prefixes, addr) != route.InvertPrefixes {
					continue
				}
			}
		}

		r.logger.Info("Matched route",
			zap.String("network", network),
			zap.String("serverName", serverName),
			zap.Stringer("sourceAddrPort", sourceAddrPort),
			zap.Stringer("targetAddr", targetAddr),
			zap.String("routeName", route.Name),
			zap.String("clientName", route.ClientName),
		)

		return route.ClientName, nil
	}

	switch network {
	case "tcp":
		return r.config.DefaultTCPClientName, nil
	case "udp":
		return r.config.DefaultUDPClientName, nil
	default:
		return "", fmt.Errorf("unknown network: %s", network)
	}
}

// lookup looks up the domain name using the specified resolver, or all resolvers if unspecified,
// and returns the lookup result, or an error if the lookup failed.
func (r *Router) lookup(domain, resolverName string) (dns.Result, error) {
	if resolverName != "" {
		resolver, ok := r.resolverMap[resolverName]
		if !ok {
			return dns.Result{}, fmt.Errorf("resolver not found: %s", resolverName)
		}
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

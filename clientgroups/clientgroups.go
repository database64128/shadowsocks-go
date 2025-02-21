// Package clientgroups provides aggregate clients that join multiple TCP and UDP clients
// into a single client group. The client group uses one of the client selection policies
// to choose a client from the group for each connection.
package clientgroups

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ClientSelectionPolicy is a client selection policy.
type ClientSelectionPolicy string

const (
	// PolicyRoundRobin selects clients in a round-robin fashion.
	PolicyRoundRobin ClientSelectionPolicy = "round-robin"

	// PolicyRandom selects clients randomly.
	PolicyRandom ClientSelectionPolicy = "random"

	// PolicyAvailability selects the client with the highest availability.
	PolicyAvailability ClientSelectionPolicy = "availability"

	// PolicyLatency selects the client with the lowest average latency.
	PolicyLatency ClientSelectionPolicy = "latency"

	// PolicyMinMaxLatency selects the client with the lowest worst latency.
	PolicyMinMaxLatency ClientSelectionPolicy = "min-max-latency"
)

// ClientGroupConfig is the configuration for a client group.
type ClientGroupConfig struct {
	// Name is the name of the client group.
	Name string `json:"name"`

	// TCPPolicy is the client selection policy for TCP clients.
	// See [ClientSelectionPolicy] for available policies.
	TCPPolicy ClientSelectionPolicy `json:"tcpPolicy"`

	// UDPPolicy is the client selection policy for UDP clients.
	// See [ClientSelectionPolicy] for available policies.
	UDPPolicy ClientSelectionPolicy `json:"udpPolicy"`

	// TCPClients is the list of TCP clients in the group, represented by their names.
	TCPClients []string `json:"tcpClients"`

	// UDPClients is the list of UDP clients in the group, represented by their names.
	UDPClients []string `json:"udpClients"`

	// TCPConnectivityProbe is the configuration for TCP connectivity probes.
	TCPConnectivityProbe TCPConnectivityProbeConfig `json:"tcpConnectivityProbe"`

	// UDPConnectivityProbe is the configuration for UDP connectivity probes.
	UDPConnectivityProbe UDPConnectivityProbeConfig `json:"udpConnectivityProbe"`
}

// AddClientGroup creates a client group from the configuration and adds it to the client maps.
func (c *ClientGroupConfig) AddClientGroup(
	logger *zap.Logger,
	tcpClientByName map[string]zerocopy.TCPClient,
	udpClientByName map[string]zerocopy.UDPClient,
	addProbeService func(shadowsocks.Service),
) error {
	if len(c.TCPClients) == 0 && len(c.UDPClients) == 0 {
		return errors.New("empty client group")
	}

	if len(c.TCPClients) > 0 {
		clients := make([]tcpClient, len(c.TCPClients))
		for i, name := range c.TCPClients {
			client, ok := tcpClientByName[name]
			if !ok {
				return fmt.Errorf("TCP client not found: %q", name)
			}
			clients[i] = newTCPClient(client)
		}

		var (
			group   zerocopy.TCPClient
			service *ProbeService[tcpClient]
		)
		switch c.TCPPolicy {
		case PolicyRoundRobin:
			group = newRoundRobinTCPClientGroup(clients)
		case PolicyRandom:
			group = newRandomTCPClientGroup(clients)
		case PolicyAvailability:
			group, service = c.TCPConnectivityProbe.newAvailabilityClientGroup(c.Name, logger, clients)
			addProbeService(service)
		case PolicyLatency:
			group, service = c.TCPConnectivityProbe.newLatencyClientGroup(c.Name, logger, clients)
			addProbeService(service)
		default:
			return fmt.Errorf("unknown TCP client selection policy: %q", c.TCPPolicy)
		}
		tcpClientByName[c.Name] = group
	}

	if len(c.UDPClients) > 0 {
		clients := make([]zerocopy.UDPClient, len(c.UDPClients))
		var info zerocopy.UDPClientInfo
		for i, name := range c.UDPClients {
			client, ok := udpClientByName[name]
			if !ok {
				return fmt.Errorf("UDP client not found: %q", name)
			}
			clients[i] = client
			info.PackerHeadroom = zerocopy.MaxHeadroom(info.PackerHeadroom, client.Info().PackerHeadroom)
		}

		var (
			group   zerocopy.UDPClient
			service *ProbeService[zerocopy.UDPClient]
		)
		switch c.UDPPolicy {
		case PolicyRoundRobin:
			group = newRoundRobinUDPClientGroup(clients, info)
		case PolicyRandom:
			group = newRandomUDPClientGroup(clients, info)
		case PolicyAvailability:
			group, service = c.UDPConnectivityProbe.newAvailabilityClientGroup(c.Name, logger, clients, info)
			addProbeService(service)
		case PolicyLatency:
			group, service = c.UDPConnectivityProbe.newLatencyClientGroup(c.Name, logger, clients, info)
			addProbeService(service)
		default:
			return fmt.Errorf("unknown UDP client selection policy: %q", c.UDPPolicy)
		}
		udpClientByName[c.Name] = group
	}

	return nil
}

type tcpClient struct {
	dialer zerocopy.TCPDialer
	info   zerocopy.TCPClientInfo
}

func newTCPClient(client zerocopy.TCPClient) tcpClient {
	dialer, info := client.NewDialer()
	return tcpClient{
		dialer: dialer,
		info:   info,
	}
}

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (c tcpClient) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return c.dialer, c.info
}

// roundRobinClientSelector is a client selector that selects clients in a round-robin fashion.
type roundRobinClientSelector[C any] struct {
	clients []C
	index   atomic.Uintptr
}

// newRoundRobinClientSelector returns a new round-robin client selector.
func newRoundRobinClientSelector[C any](clients []C) *roundRobinClientSelector[C] {
	g := roundRobinClientSelector[C]{
		clients: clients,
	}
	g.index.Store(^uintptr(0))
	return &g
}

// Select selects a client in a round-robin fashion.
func (s *roundRobinClientSelector[C]) Select() C {
	const uintptrToNonNegativeInt = ^uintptr(0) >> 1
	return s.clients[int(s.index.Add(1)&uintptrToNonNegativeInt)%len(s.clients)]
}

// roundRobinTCPClientGroup is a TCP client group that selects clients in a round-robin fashion.
//
// roundRobinTCPClientGroup implements [zerocopy.TCPClient].
type roundRobinTCPClientGroup struct {
	selector roundRobinClientSelector[tcpClient]
}

// newRoundRobinTCPClientGroup returns a new round-robin TCP client group.
func newRoundRobinTCPClientGroup(clients []tcpClient) *roundRobinTCPClientGroup {
	return &roundRobinTCPClientGroup{
		selector: *newRoundRobinClientSelector(clients),
	}
}

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (g *roundRobinTCPClientGroup) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return g.selector.Select().NewDialer()
}

// roundRobinUDPClientGroup is a UDP client group that selects clients in a round-robin fashion.
//
// roundRobinUDPClientGroup implements [zerocopy.UDPClient].
type roundRobinUDPClientGroup struct {
	selector roundRobinClientSelector[zerocopy.UDPClient]
	info     zerocopy.UDPClientInfo
}

// newRoundRobinUDPClientGroup returns a new round-robin UDP client group.
func newRoundRobinUDPClientGroup(clients []zerocopy.UDPClient, info zerocopy.UDPClientInfo) *roundRobinUDPClientGroup {
	return &roundRobinUDPClientGroup{
		selector: *newRoundRobinClientSelector(clients),
		info:     info,
	}
}

// Info implements [zerocopy.UDPClient.Info].
func (g *roundRobinUDPClientGroup) Info() zerocopy.UDPClientInfo {
	return g.info
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (g *roundRobinUDPClientGroup) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return g.selector.Select().NewSession(ctx)
}

// randomClientSelector is a client selector that selects clients randomly.
type randomClientSelector[C any] struct {
	clients []C
}

// newRandomClientSelector returns a new random client selector.
func newRandomClientSelector[C any](clients []C) *randomClientSelector[C] {
	return &randomClientSelector[C]{
		clients: clients,
	}
}

// Select selects a client randomly.
func (s *randomClientSelector[C]) Select() C {
	return s.clients[rand.IntN(len(s.clients))]
}

// randomTCPClientGroup is a TCP client group that selects clients randomly.
//
// randomTCPClientGroup implements [zerocopy.TCPClient].
type randomTCPClientGroup struct {
	selector randomClientSelector[tcpClient]
}

// newRandomTCPClientGroup returns a new random TCP client group.
func newRandomTCPClientGroup(clients []tcpClient) *randomTCPClientGroup {
	return &randomTCPClientGroup{
		selector: *newRandomClientSelector(clients),
	}
}

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (g *randomTCPClientGroup) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return g.selector.Select().NewDialer()
}

// randomUDPClientGroup is a UDP client group that selects clients randomly.
//
// randomUDPClientGroup implements [zerocopy.UDPClient].
type randomUDPClientGroup struct {
	selector randomClientSelector[zerocopy.UDPClient]
	info     zerocopy.UDPClientInfo
}

// newRandomUDPClientGroup returns a new random UDP client group.
func newRandomUDPClientGroup(clients []zerocopy.UDPClient, info zerocopy.UDPClientInfo) *randomUDPClientGroup {
	return &randomUDPClientGroup{
		selector: *newRandomClientSelector(clients),
		info:     info,
	}
}

// Info implements [zerocopy.UDPClient.Info].
func (g *randomUDPClientGroup) Info() zerocopy.UDPClientInfo {
	return g.info
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (g *randomUDPClientGroup) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return g.selector.Select().NewSession(ctx)
}

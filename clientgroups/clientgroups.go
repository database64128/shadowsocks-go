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
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
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

// ClientSelectionConfig is the configuration for client selection.
type ClientSelectionConfig[PC TCPConnectivityProbeConfig | UDPConnectivityProbeConfig] struct {
	// Policy is the client selection policy.
	// See [ClientSelectionPolicy] for available policies.
	Policy ClientSelectionPolicy `json:"policy"`

	// Clients is the list of clients in the group, represented by their names.
	Clients []string `json:"clients"`

	// Probe is the configuration for connectivity probes.
	Probe PC `json:"probe,omitzero"`
}

// ClientGroupConfig is the configuration for a client group.
type ClientGroupConfig struct {
	// Name is the name of the client group.
	Name string `json:"name"`

	// TCP is the client selection configuration for TCP clients.
	TCP ClientSelectionConfig[TCPConnectivityProbeConfig] `json:"tcp,omitzero"`

	// UDP is the client selection configuration for UDP clients.
	UDP ClientSelectionConfig[UDPConnectivityProbeConfig] `json:"udp,omitzero"`
}

// AddClientGroup creates a client group from the configuration and adds it to the client maps.
func (c *ClientGroupConfig) AddClientGroup(
	logger *zap.Logger,
	tcpClientByName map[string]netio.StreamClient,
	udpClientByName map[string]zerocopy.UDPClient,
	addProbeService func(shadowsocks.Service),
) error {
	if len(c.TCP.Clients) == 0 && len(c.UDP.Clients) == 0 {
		return errors.New("empty client group")
	}

	if len(c.TCP.Clients) > 0 {
		clients := make([]tcpClient, len(c.TCP.Clients))
		for i, name := range c.TCP.Clients {
			client, ok := tcpClientByName[name]
			if !ok {
				return fmt.Errorf("TCP client not found: %q", name)
			}
			clients[i] = newTCPClient(client)
		}

		var (
			group   netio.StreamClient
			service *ProbeService[tcpClient]
		)
		switch c.TCP.Policy {
		case PolicyRoundRobin:
			group = newRoundRobinTCPClientGroup(clients)
		case PolicyRandom:
			group = newRandomTCPClientGroup(clients)
		case PolicyAvailability:
			group, service = c.TCP.Probe.newAvailabilityClientGroup(c.Name, logger, clients)
			addProbeService(service)
		case PolicyLatency:
			group, service = c.TCP.Probe.newLatencyClientGroup(c.Name, logger, clients)
			addProbeService(service)
		case PolicyMinMaxLatency:
			group, service = c.TCP.Probe.newMinMaxLatencyClientGroup(c.Name, logger, clients)
			addProbeService(service)
		default:
			return fmt.Errorf("unknown TCP client selection policy: %q", c.TCP.Policy)
		}
		tcpClientByName[c.Name] = group
	}

	if len(c.UDP.Clients) > 0 {
		clients := make([]zerocopy.UDPClient, len(c.UDP.Clients))
		var info zerocopy.UDPClientInfo
		for i, name := range c.UDP.Clients {
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
		switch c.UDP.Policy {
		case PolicyRoundRobin:
			group = newRoundRobinUDPClientGroup(clients, info)
		case PolicyRandom:
			group = newRandomUDPClientGroup(clients, info)
		case PolicyAvailability:
			group, service = c.UDP.Probe.newAvailabilityClientGroup(c.Name, logger, clients, info)
			addProbeService(service)
		case PolicyLatency:
			group, service = c.UDP.Probe.newLatencyClientGroup(c.Name, logger, clients, info)
			addProbeService(service)
		case PolicyMinMaxLatency:
			group, service = c.UDP.Probe.newMinMaxLatencyClientGroup(c.Name, logger, clients, info)
			addProbeService(service)
		default:
			return fmt.Errorf("unknown UDP client selection policy: %q", c.UDP.Policy)
		}
		udpClientByName[c.Name] = group
	}

	return nil
}

type tcpClient struct {
	dialer netio.StreamDialer
	info   netio.StreamDialerInfo
}

func newTCPClient(client netio.StreamClient) tcpClient {
	dialer, info := client.NewStreamDialer()
	return tcpClient{
		dialer: dialer,
		info:   info,
	}
}

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (c tcpClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c.dialer, c.info
}

// DialStream implements [netio.StreamDialer.DialStream].
func (c tcpClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (netio.Conn, error) {
	return c.dialer.DialStream(ctx, addr, payload)
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
// roundRobinTCPClientGroup implements [netio.StreamClient] and [netio.StreamDialer].
type roundRobinTCPClientGroup struct {
	selector roundRobinClientSelector[tcpClient]
}

// newRoundRobinTCPClientGroup returns a new round-robin TCP client group.
func newRoundRobinTCPClientGroup(clients []tcpClient) *roundRobinTCPClientGroup {
	return &roundRobinTCPClientGroup{
		selector: *newRoundRobinClientSelector(clients),
	}
}

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (g *roundRobinTCPClientGroup) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return g.selector.Select().NewStreamDialer()
}

// DialStream implements [netio.StreamDialer.DialStream].
func (g *roundRobinTCPClientGroup) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (netio.Conn, error) {
	return g.selector.Select().DialStream(ctx, addr, payload)
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
// randomTCPClientGroup implements [netio.StreamClient] and [netio.StreamDialer].
type randomTCPClientGroup struct {
	selector randomClientSelector[tcpClient]
}

// newRandomTCPClientGroup returns a new random TCP client group.
func newRandomTCPClientGroup(clients []tcpClient) *randomTCPClientGroup {
	return &randomTCPClientGroup{
		selector: *newRandomClientSelector(clients),
	}
}

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (g *randomTCPClientGroup) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return g.selector.Select().NewStreamDialer()
}

// DialStream implements [netio.StreamDialer.DialStream].
func (g *randomTCPClientGroup) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (netio.Conn, error) {
	return g.selector.Select().DialStream(ctx, addr, payload)
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

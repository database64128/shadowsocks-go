package clientgroups

import (
	"context"
	"fmt"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/jsonhelper"
	"github.com/database64128/shadowsocks-go/probe"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

const (
	defaultProbeTimeout     = 5 * time.Second
	defaultProbeInterval    = 30 * time.Second
	defaultProbeConcurrency = 32

	defaultTCPProbeEscapedPath = "/generate_204"
	defaultTCPProbeHost        = "clients3.google.com"
)

var (
	// https://www.chromium.org/chromium-os/chromiumos-design-docs/network-portal-detection/
	defaultTCPProbeAddress = conn.MustAddrFromDomainPort("clients3.google.com", 80)

	// [2606:4700:4700::1111]:53
	defaultUDPProbeAddress = conn.AddrFromIPPort(netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 14: 0x11, 0x11}), 53))
)

// ConnectivityProbeConfig is the shared part of the configuration for TCP and UDP connectivity probes.
type ConnectivityProbeConfig struct {
	// Timeout is the timeout for each connectivity test.
	//
	// Default is 5 seconds.
	Timeout jsonhelper.Duration `json:"timeout"`

	// Interval is the interval between connectivity tests.
	//
	// Default is 30 seconds.
	Interval jsonhelper.Duration `json:"interval"`

	// Concurrency is the maximum number of concurrent connectivity tests.
	//
	// Default is 32.
	Concurrency int `json:"concurrency"`
}

func (c *ConnectivityProbeConfig) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = jsonhelper.Duration(defaultProbeTimeout)
	}
	if c.Interval <= 0 {
		c.Interval = jsonhelper.Duration(defaultProbeInterval)
	}
	if c.Concurrency <= 0 {
		c.Concurrency = defaultProbeConcurrency
	}
}

// TCPConnectivityProbeConfig controls how TCP clients are probed
// when the client selection policy requires doing connectivity probes.
type TCPConnectivityProbeConfig struct {
	ConnectivityProbeConfig

	// Address is the address of the HTTP test endpoint.
	Address conn.Addr `json:"address"`

	// EscapedPath is the escaped URL path of the HTTP test endpoint.
	EscapedPath string `json:"escapedPath"`

	// Host specifies the value of the Host header field in the HTTP request.
	Host string `json:"host"`
}

func (c TCPConnectivityProbeConfig) newAvailabilityClientGroup(
	name string,
	logger *zap.Logger,
	clients []tcpClient,
) (*availabilityTCPClientGroup, *ProbeService) {
	g := &availabilityTCPClientGroup{
		selector: *newAvailabilityClientSelector(&clients[0]),
	}
	pc := c.newProbeConfig(clients)
	logger = logger.With(
		zap.String("clientGroup", name),
		zap.String("address", c.Address.String()),
		zap.String("escapedPath", c.EscapedPath),
		zap.String("host", c.Host),
		zap.Duration("timeout", pc.timeout),
		zap.Duration("interval", pc.interval),
		zap.Int("concurrency", pc.concurrency),
		zap.Int("clients", len(pc.clients)),
	)
	return g, NewProbeService(
		fmt.Sprintf("TCP connectivity probe for %s", name),
		func(ctx context.Context) error {
			go g.selector.probe(ctx, logger, pc)
			return nil
		},
	)
}

func (c TCPConnectivityProbeConfig) newProbeConfig(clients []tcpClient) probeConfig[tcpClient] {
	c.applyDefaults()
	tpc := probe.TCPProbeConfig{
		Addr:        c.Address,
		EscapedPath: c.EscapedPath,
		Host:        c.Host,
	}
	tp := tpc.NewProbe()
	return probeConfig[tcpClient]{
		probe: func(ctx context.Context, client tcpClient) error {
			return tp.Probe(ctx, client)
		},
		timeout:     c.Timeout.Value(),
		interval:    c.Interval.Value(),
		concurrency: min(c.Concurrency, len(clients)),
		clients:     clients,
	}
}

func (c *TCPConnectivityProbeConfig) applyDefaults() {
	c.ConnectivityProbeConfig.applyDefaults()
	if !c.Address.IsValid() {
		c.Address = defaultTCPProbeAddress
	}
	if c.EscapedPath == "" {
		c.EscapedPath = defaultTCPProbeEscapedPath
	}
	if c.Host == "" {
		c.Host = defaultTCPProbeHost
	}
}

// UDPConnectivityProbeConfig controls how UDP clients are probed
// when the client selection policy requires doing connectivity probes.
type UDPConnectivityProbeConfig struct {
	ConnectivityProbeConfig

	// Address is the address of the UDP DNS server.
	Address conn.Addr `json:"address"`
}

func (c UDPConnectivityProbeConfig) newAvailabilityClientGroup(
	name string,
	logger *zap.Logger,
	clients []zerocopy.UDPClient,
	info zerocopy.UDPClientInfo,
) (*availabilityUDPClientGroup, *ProbeService) {
	g := &availabilityUDPClientGroup{
		selector: *newAvailabilityClientSelector(&clients[0]),
		info:     info,
	}
	pc := c.newProbeConfig(logger, clients)
	logger = logger.With(
		zap.String("clientGroup", name),
		zap.String("address", c.Address.String()),
		zap.Duration("timeout", pc.timeout),
		zap.Duration("interval", pc.interval),
		zap.Int("concurrency", pc.concurrency),
		zap.Int("clients", len(pc.clients)),
	)
	return g, NewProbeService(
		fmt.Sprintf("UDP connectivity probe for %s", name),
		func(ctx context.Context) error {
			go g.selector.probe(ctx, logger, pc)
			return nil
		},
	)
}

func (c UDPConnectivityProbeConfig) newProbeConfig(logger *zap.Logger, clients []zerocopy.UDPClient) probeConfig[zerocopy.UDPClient] {
	c.applyDefaults()
	upc := probe.UDPProbeConfig{
		Addr:   c.Address,
		Logger: logger,
	}
	return probeConfig[zerocopy.UDPClient]{
		probe:       upc.NewProbe().Probe,
		timeout:     c.Timeout.Value(),
		interval:    c.Interval.Value(),
		concurrency: min(c.Concurrency, len(clients)),
		clients:     clients,
	}
}

func (c *UDPConnectivityProbeConfig) applyDefaults() {
	c.ConnectivityProbeConfig.applyDefaults()
	if !c.Address.IsValid() {
		c.Address = defaultUDPProbeAddress
	}
}

type probeConfig[C any] struct {
	probe       func(ctx context.Context, client C) error
	timeout     time.Duration
	interval    time.Duration
	concurrency int
	clients     []C
}

// ProbeService runs the probe loop.
//
// ProbeService implements [service.Service].
type ProbeService struct {
	name  string
	start func(ctx context.Context) error
}

// NewProbeService returns a new probe service.
func NewProbeService(name string, start func(ctx context.Context) error) *ProbeService {
	return &ProbeService{
		name:  name,
		start: start,
	}
}

// String implements [service.Service.String].
func (s *ProbeService) String() string {
	return s.name
}

// Start implements [service.Service.Start].
func (s *ProbeService) Start(ctx context.Context) error {
	return s.start(ctx)
}

// Stop implements [service.Service.Stop].
func (*ProbeService) Stop() error {
	return nil
}

// availabilityClientSelector is a client selector that selects clients based on availability.
// It tests the internet connectivity of each client and selects the one with the highest success rate.
type availabilityClientSelector[C any] struct {
	selected atomic.Pointer[C]
}

// newAvailabilityClientSelector returns a new availability client selector.
func newAvailabilityClientSelector[C any](initialClient *C) *availabilityClientSelector[C] {
	var s availabilityClientSelector[C]
	s.selected.Store(initialClient)
	return &s
}

// Select selects the best available client.
func (s *availabilityClientSelector[C]) Select() C {
	return *s.selected.Load()
}

// probe runs the availability probe loop.
func (s *availabilityClientSelector[C]) probe(
	ctx context.Context,
	logger *zap.Logger,
	pc probeConfig[C],
) {
	// Start probe workers.
	jobCh := make(chan availabilityProbeJob[C])
	defer close(jobCh)
	for range pc.concurrency {
		go func() {
			for job := range jobCh {
				job.Run(ctx)
			}
		}()
	}

	// Send probe jobs.
	done := ctx.Done()
	ticker := time.NewTicker(pc.interval) // Should we use a timer instead and add some random jitter?
	defer ticker.Stop()
	var (
		wg          sync.WaitGroup
		probeResult = make([]uint, len(pc.clients))
		probeCount  uint
		clientIndex int
	)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if ce := logger.Check(zap.DebugLevel, "Started availability probe"); ce != nil {
				ce.Write(
					zap.Uint("probeCount", probeCount),
				)
			}

			wg.Add(len(pc.clients))
			for i, client := range pc.clients {
				jobCh <- availabilityProbeJob[C]{
					wg:      &wg,
					probe:   pc.probe,
					timeout: pc.timeout,
					client:  client,
					result:  &probeResult[i],
					count:   probeCount,
				}
			}
			wg.Wait()
			probeCount++

			var (
				bestIndex        int
				bestSuccessCount int
			)
			for i, result := range probeResult {
				successCount := bits.OnesCount(result)
				if successCount > bestSuccessCount {
					bestIndex = i
					bestSuccessCount = successCount
				}
				if ce := logger.Check(zap.DebugLevel, "Availability probe result"); ce != nil {
					ce.Write(
						zap.Int("client", i),
						zap.Int("successCount", successCount),
					)
				}
			}
			if ce := logger.Check(zap.DebugLevel, "Finished availability probe"); ce != nil {
				ce.Write(
					zap.Int("oldClient", clientIndex),
					zap.Int("newClient", bestIndex),
				)
			}
			if clientIndex != bestIndex {
				clientIndex = bestIndex
				s.selected.Store(&pc.clients[clientIndex])
			}
		}
	}
}

type availabilityProbeJob[C any] struct {
	wg      *sync.WaitGroup
	probe   func(ctx context.Context, client C) error
	timeout time.Duration
	client  C
	result  *uint
	count   uint
}

func (j *availabilityProbeJob[C]) Run(ctx context.Context) {
	defer j.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()
	mask := uint(1) << (j.count % bits.UintSize)
	if err := j.probe(ctx, j.client); err == nil {
		*j.result |= mask
	} else {
		*j.result &^= mask
	}
}

// availabilityTCPClientGroup is a TCP client group that selects clients based on availability.
//
// availabilityTCPClientGroup implements [zerocopy.TCPClient].
type availabilityTCPClientGroup struct {
	selector availabilityClientSelector[tcpClient]
}

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (g *availabilityTCPClientGroup) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return g.selector.Select().NewDialer()
}

// availabilityUDPClientGroup is a UDP client group that selects clients based on availability.
//
// availabilityUDPClientGroup implements [zerocopy.UDPClient].
type availabilityUDPClientGroup struct {
	selector availabilityClientSelector[zerocopy.UDPClient]
	info     zerocopy.UDPClientInfo
}

// Info implements [zerocopy.UDPClient.Info].
func (g *availabilityUDPClientGroup) Info() zerocopy.UDPClientInfo {
	return g.info
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (g *availabilityUDPClientGroup) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return g.selector.Select().NewSession(ctx)
}

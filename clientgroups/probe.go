package clientgroups

import (
	"context"
	"math/bits"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go"
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
	//
	// Default is "clients3.google.com:80".
	Address conn.Addr `json:"address"`

	// EscapedPath is the escaped URL path of the HTTP test endpoint.
	//
	// Default is "/generate_204".
	EscapedPath string `json:"escapedPath"`

	// Host specifies the value of the Host header field in the HTTP request.
	//
	// Default is "clients3.google.com".
	Host string `json:"host"`
}

// newAvailabilityClientGroup returns a new availability client group for the given TCP clients.
// It tests the internet connectivity of each client and selects the one with the highest success rate.
func (c *TCPConnectivityProbeConfig) newAvailabilityClientGroup(
	name string,
	logger *zap.Logger,
	clients []tcpClient,
) (*atomicTCPClientGroup, *ProbeService[tcpClient]) {
	return c.newAtomicClientGroup(name, logger, clients, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[tcpClient], pc probeConfig[tcpClient]) error {
		go selector.probeAvailability(ctx, logger, pc)
		return nil
	})
}

// newLatencyClientGroup returns a new latency client group for the given TCP clients.
// It tests the internet connectivity of each client and selects the one with the lowest average latency.
func (c *TCPConnectivityProbeConfig) newLatencyClientGroup(
	name string,
	logger *zap.Logger,
	clients []tcpClient,
) (*atomicTCPClientGroup, *ProbeService[tcpClient]) {
	return c.newAtomicClientGroup(name, logger, clients, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[tcpClient], pc probeConfig[tcpClient]) error {
		go selector.probeLatency(ctx, logger, pc)
		return nil
	})
}

// newMinMaxLatencyClientGroup returns a new minimum maximum latency client group for the given TCP clients.
// It tests the internet connectivity of each client and selects the one with the lowest worst latency.
func (c *TCPConnectivityProbeConfig) newMinMaxLatencyClientGroup(
	name string,
	logger *zap.Logger,
	clients []tcpClient,
) (*atomicTCPClientGroup, *ProbeService[tcpClient]) {
	return c.newAtomicClientGroup(name, logger, clients, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[tcpClient], pc probeConfig[tcpClient]) error {
		go selector.probeMinMaxLatency(ctx, logger, pc)
		return nil
	})
}

func (c *TCPConnectivityProbeConfig) newAtomicClientGroup(
	name string,
	logger *zap.Logger,
	clients []tcpClient,
	start func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[tcpClient], pc probeConfig[tcpClient]) error,
) (*atomicTCPClientGroup, *ProbeService[tcpClient]) {
	g := &atomicTCPClientGroup{
		selector: *newAtomicClientSelector(&clients[0]),
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
	return g, NewProbeService(zap.String("clientGroupTCPProbe", name), logger, &g.selector, pc, start)
}

func (c *TCPConnectivityProbeConfig) newProbeConfig(clients []tcpClient) probeConfig[tcpClient] {
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
	//
	// Default is "[2606:4700:4700::1111]:53".
	Address conn.Addr `json:"address"`
}

// newAvailabilityClientGroup returns a new availability client group for the given UDP clients.
// It tests the internet connectivity of each client and selects the one with the highest success rate.
func (c *UDPConnectivityProbeConfig) newAvailabilityClientGroup(
	name string,
	logger *zap.Logger,
	clients []zerocopy.UDPClient,
	info zerocopy.UDPClientInfo,
) (*atomicUDPClientGroup, *ProbeService[zerocopy.UDPClient]) {
	return c.newAtomicClientGroup(name, logger, clients, info, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[zerocopy.UDPClient], pc probeConfig[zerocopy.UDPClient]) error {
		go selector.probeAvailability(ctx, logger, pc)
		return nil
	})
}

// newLatencyClientGroup returns a new latency client group for the given UDP clients.
// It tests the internet connectivity of each client and selects the one with the lowest average latency.
func (c *UDPConnectivityProbeConfig) newLatencyClientGroup(
	name string,
	logger *zap.Logger,
	clients []zerocopy.UDPClient,
	info zerocopy.UDPClientInfo,
) (*atomicUDPClientGroup, *ProbeService[zerocopy.UDPClient]) {
	return c.newAtomicClientGroup(name, logger, clients, info, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[zerocopy.UDPClient], pc probeConfig[zerocopy.UDPClient]) error {
		go selector.probeLatency(ctx, logger, pc)
		return nil
	})
}

// newMinMaxLatencyClientGroup returns a new minimum maximum latency client group for the given UDP clients.
// It tests the internet connectivity of each client and selects the one with the lowest worst latency.
func (c *UDPConnectivityProbeConfig) newMinMaxLatencyClientGroup(
	name string,
	logger *zap.Logger,
	clients []zerocopy.UDPClient,
	info zerocopy.UDPClientInfo,
) (*atomicUDPClientGroup, *ProbeService[zerocopy.UDPClient]) {
	return c.newAtomicClientGroup(name, logger, clients, info, func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[zerocopy.UDPClient], pc probeConfig[zerocopy.UDPClient]) error {
		go selector.probeMinMaxLatency(ctx, logger, pc)
		return nil
	})
}

func (c *UDPConnectivityProbeConfig) newAtomicClientGroup(
	name string,
	logger *zap.Logger,
	clients []zerocopy.UDPClient,
	info zerocopy.UDPClientInfo,
	start func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[zerocopy.UDPClient], pc probeConfig[zerocopy.UDPClient]) error,
) (*atomicUDPClientGroup, *ProbeService[zerocopy.UDPClient]) {
	g := &atomicUDPClientGroup{
		selector: *newAtomicClientSelector(&clients[0]),
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
	return g, NewProbeService(zap.String("clientGroupUDPProbe", name), logger, &g.selector, pc, start)
}

func (c *UDPConnectivityProbeConfig) newProbeConfig(logger *zap.Logger, clients []zerocopy.UDPClient) probeConfig[zerocopy.UDPClient] {
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
// ProbeService implements [shadowsocks.Service].
type ProbeService[C any] struct {
	zapField zap.Field
	logger   *zap.Logger
	selector *atomicClientSelector[C]
	pc       probeConfig[C]
	start    func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[C], pc probeConfig[C]) error
}

// NewProbeService returns a new probe service.
func NewProbeService[C any](
	zapField zap.Field,
	logger *zap.Logger,
	selector *atomicClientSelector[C],
	pc probeConfig[C],
	start func(ctx context.Context, logger *zap.Logger, selector *atomicClientSelector[C], pc probeConfig[C]) error,
) *ProbeService[C] {
	return &ProbeService[C]{
		zapField: zapField,
		logger:   logger,
		selector: selector,
		pc:       pc,
		start:    start,
	}
}

var _ shadowsocks.Service = (*ProbeService[any])(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (s *ProbeService[C]) ZapField() zap.Field {
	return s.zapField
}

// Start implements [shadowsocks.Service.Start].
func (s *ProbeService[C]) Start(ctx context.Context) error {
	return s.start(ctx, s.logger, s.selector, s.pc)
}

// Stop implements [shadowsocks.Service.Stop].
func (*ProbeService[C]) Stop() error {
	return nil
}

// atomicClientSelector is a client selector that allows the selected client to be atomically changed.
type atomicClientSelector[C any] struct {
	selected atomic.Pointer[C]
}

// newAtomicClientSelector returns a new atomic client selector.
func newAtomicClientSelector[C any](initialClient *C) *atomicClientSelector[C] {
	var s atomicClientSelector[C]
	s.selected.Store(initialClient)
	return &s
}

// Select returns the selected client.
func (s *atomicClientSelector[C]) Select() C {
	return *s.selected.Load()
}

// probeAvailability runs the availability probe loop.
func (s *atomicClientSelector[C]) probeAvailability(
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

const latencyProbeResultSize = 32

// probeLatency runs the latency probe loop.
func (s *atomicClientSelector[C]) probeLatency(
	ctx context.Context,
	logger *zap.Logger,
	pc probeConfig[C],
) {
	// Start probe workers.
	jobCh := make(chan latencyProbeJob[C])
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
		probeResult = make([][latencyProbeResultSize]time.Duration, len(pc.clients))
		probeCount  uint
		clientIndex int
	)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if ce := logger.Check(zap.DebugLevel, "Started latency probe"); ce != nil {
				ce.Write(
					zap.Uint("probeCount", probeCount),
				)
			}

			wg.Add(len(pc.clients))
			for i, client := range pc.clients {
				jobCh <- latencyProbeJob[C]{
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
				bestIndex      int
				bestAvgLatency = pc.timeout
			)
			for i, result := range probeResult {
				var avgLatency time.Duration
				for _, latency := range result {
					avgLatency += latency
				}
				avgLatency /= time.Duration(len(result))
				if avgLatency < bestAvgLatency {
					bestIndex = i
					bestAvgLatency = avgLatency
				}
				if ce := logger.Check(zap.DebugLevel, "Latency probe result"); ce != nil {
					ce.Write(
						zap.Int("client", i),
						zap.Duration("avgLatency", avgLatency),
					)
				}
			}
			if ce := logger.Check(zap.DebugLevel, "Finished latency probe"); ce != nil {
				ce.Write(
					zap.Int("oldClient", clientIndex),
					zap.Int("newClient", bestIndex),
					zap.Duration("avgLatency", bestAvgLatency),
				)
			}
			if clientIndex != bestIndex {
				clientIndex = bestIndex
				s.selected.Store(&pc.clients[clientIndex])
			}
		}
	}
}

// probeMinMaxLatency runs the minimum maximum latency probe loop.
func (s *atomicClientSelector[C]) probeMinMaxLatency(
	ctx context.Context,
	logger *zap.Logger,
	pc probeConfig[C],
) {
	// Start probe workers.
	jobCh := make(chan latencyProbeJob[C])
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
		probeResult = make([][latencyProbeResultSize]time.Duration, len(pc.clients))
		probeCount  uint
		clientIndex int
	)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if ce := logger.Check(zap.DebugLevel, "Started latency probe"); ce != nil {
				ce.Write(
					zap.Uint("probeCount", probeCount),
				)
			}

			wg.Add(len(pc.clients))
			for i, client := range pc.clients {
				jobCh <- latencyProbeJob[C]{
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
				bestIndex      int
				bestMaxLatency = pc.timeout
			)
			for i, result := range probeResult {
				maxLatency := slices.Max(result[:])
				if maxLatency < bestMaxLatency {
					bestIndex = i
					bestMaxLatency = maxLatency
				}
				if ce := logger.Check(zap.DebugLevel, "Latency probe result"); ce != nil {
					ce.Write(
						zap.Int("client", i),
						zap.Duration("maxLatency", maxLatency),
					)
				}
			}
			if ce := logger.Check(zap.DebugLevel, "Finished latency probe"); ce != nil {
				ce.Write(
					zap.Int("oldClient", clientIndex),
					zap.Int("newClient", bestIndex),
					zap.Duration("maxLatency", bestMaxLatency),
				)
			}
			if clientIndex != bestIndex {
				clientIndex = bestIndex
				s.selected.Store(&pc.clients[clientIndex])
			}
		}
	}
}

type latencyProbeJob[C any] struct {
	wg      *sync.WaitGroup
	probe   func(ctx context.Context, client C) error
	timeout time.Duration
	client  C
	result  *[latencyProbeResultSize]time.Duration
	count   uint
}

func (j *latencyProbeJob[C]) Run(ctx context.Context) {
	defer j.wg.Done()
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(j.timeout))
	defer cancel()
	if err := j.probe(ctx, j.client); err == nil {
		j.result[j.count%latencyProbeResultSize] = time.Since(start)
	} else {
		j.result[j.count%latencyProbeResultSize] = j.timeout
	}
}

// atomicTCPClientGroup is a TCP client group that wraps an atomic client selector.
//
// atomicTCPClientGroup implements [zerocopy.TCPClient].
type atomicTCPClientGroup struct {
	selector atomicClientSelector[tcpClient]
}

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (g *atomicTCPClientGroup) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return g.selector.Select().NewDialer()
}

// atomicUDPClientGroup is a UDP client group that wraps an atomic client selector.
//
// atomicUDPClientGroup implements [zerocopy.UDPClient].
type atomicUDPClientGroup struct {
	selector atomicClientSelector[zerocopy.UDPClient]
	info     zerocopy.UDPClientInfo
}

// Info implements [zerocopy.UDPClient.Info].
func (g *atomicUDPClientGroup) Info() zerocopy.UDPClientInfo {
	return g.info
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (g *atomicUDPClientGroup) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return g.selector.Select().NewSession(ctx)
}

package stats

import (
	"sync"
	"sync/atomic"

	"github.com/database64128/shadowsocks-go/cmp"
	"github.com/database64128/shadowsocks-go/slices"
)

type trafficCollector struct {
	downlinkPackets atomic.Uint64
	downlinkBytes   atomic.Uint64
	uplinkPackets   atomic.Uint64
	uplinkBytes     atomic.Uint64
	tcpSessions     atomic.Uint64
	udpSessions     atomic.Uint64
}

func (tc *trafficCollector) collectTCPSession(downlinkBytes, uplinkBytes uint64) {
	tc.downlinkBytes.Add(downlinkBytes)
	tc.uplinkBytes.Add(uplinkBytes)
	tc.tcpSessions.Add(1)
}

func (tc *trafficCollector) collectUDPSessionDownlink(downlinkPackets, downlinkBytes uint64) {
	tc.downlinkPackets.Add(downlinkPackets)
	tc.downlinkBytes.Add(downlinkBytes)
	tc.udpSessions.Add(1)
}

func (tc *trafficCollector) collectUDPSessionUplink(uplinkPackets, uplinkBytes uint64) {
	tc.uplinkPackets.Add(uplinkPackets)
	tc.uplinkBytes.Add(uplinkBytes)
}

// Traffic stores the traffic statistics.
type Traffic struct {
	DownlinkPackets uint64 `json:"downlinkPackets"`
	DownlinkBytes   uint64 `json:"downlinkBytes"`
	UplinkPackets   uint64 `json:"uplinkPackets"`
	UplinkBytes     uint64 `json:"uplinkBytes"`
	TCPSessions     uint64 `json:"tcpSessions"`
	UDPSessions     uint64 `json:"udpSessions"`
}

func (t *Traffic) Add(u Traffic) {
	t.DownlinkPackets += u.DownlinkPackets
	t.DownlinkBytes += u.DownlinkBytes
	t.UplinkPackets += u.UplinkPackets
	t.UplinkBytes += u.UplinkBytes
	t.TCPSessions += u.TCPSessions
	t.UDPSessions += u.UDPSessions
}

func (tc *trafficCollector) snapshot() Traffic {
	return Traffic{
		DownlinkPackets: tc.downlinkPackets.Load(),
		DownlinkBytes:   tc.downlinkBytes.Load(),
		UplinkPackets:   tc.uplinkPackets.Load(),
		UplinkBytes:     tc.uplinkBytes.Load(),
		TCPSessions:     tc.tcpSessions.Load(),
		UDPSessions:     tc.udpSessions.Load(),
	}
}

func (tc *trafficCollector) snapshotAndReset() Traffic {
	return Traffic{
		DownlinkPackets: tc.downlinkPackets.Swap(0),
		DownlinkBytes:   tc.downlinkBytes.Swap(0),
		UplinkPackets:   tc.uplinkPackets.Swap(0),
		UplinkBytes:     tc.uplinkBytes.Swap(0),
		TCPSessions:     tc.tcpSessions.Swap(0),
		UDPSessions:     tc.udpSessions.Swap(0),
	}
}

type userCollector struct {
	trafficCollector
}

// User stores the user's traffic statistics.
type User struct {
	Name string `json:"username"`
	Traffic
}

// Compare is useful for sorting users by name.
func (u User) Compare(other User) int {
	return cmp.Compare(u.Name, other.Name)
}

func (uc *userCollector) snapshot(username string) User {
	return User{
		Name:    username,
		Traffic: uc.trafficCollector.snapshot(),
	}
}

func (uc *userCollector) snapshotAndReset(username string) User {
	return User{
		Name:    username,
		Traffic: uc.trafficCollector.snapshotAndReset(),
	}
}

type serverCollector struct {
	tc  trafficCollector
	ucs map[string]*userCollector
	mu  sync.RWMutex
}

// NewServerCollector returns a new collector for collecting server traffic statistics.
func NewServerCollector() *serverCollector {
	return &serverCollector{
		ucs: make(map[string]*userCollector),
	}
}

func (sc *serverCollector) userCollector(username string) *userCollector {
	sc.mu.RLock()
	uc := sc.ucs[username]
	sc.mu.RUnlock()
	if uc == nil {
		sc.mu.Lock()
		uc = sc.ucs[username]
		if uc == nil {
			uc = &userCollector{}
			sc.ucs[username] = uc
		}
		sc.mu.Unlock()
	}
	return uc
}

func (sc *serverCollector) trafficCollector(username string) *trafficCollector {
	if username == "" {
		return &sc.tc
	}
	return &sc.userCollector(username).trafficCollector
}

// CollectTCPSession implements the Collector CollectTCPSession method.
func (sc *serverCollector) CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64) {
	sc.trafficCollector(username).collectTCPSession(downlinkBytes, uplinkBytes)
}

// CollectUDPSessionDownlink implements the Collector CollectUDPSessionDownlink method.
func (sc *serverCollector) CollectUDPSessionDownlink(username string, downlinkPackets, downlinkBytes uint64) {
	sc.trafficCollector(username).collectUDPSessionDownlink(downlinkPackets, downlinkBytes)
}

// CollectUDPSessionUplink implements the Collector CollectUDPSessionUplink method.
func (sc *serverCollector) CollectUDPSessionUplink(username string, uplinkPackets, uplinkBytes uint64) {
	sc.trafficCollector(username).collectUDPSessionUplink(uplinkPackets, uplinkBytes)
}

// Server stores the server's traffic statistics.
type Server struct {
	Traffic
	Users []User `json:"users,omitempty"`
}

// Snapshot implements the Collector Snapshot method.
func (sc *serverCollector) Snapshot() (s Server) {
	s.Traffic = sc.tc.snapshot()
	sc.mu.RLock()
	s.Users = make([]User, 0, len(sc.ucs))
	for username, uc := range sc.ucs {
		u := uc.snapshot(username)
		s.Traffic.Add(u.Traffic)
		s.Users = append(s.Users, u)
	}
	sc.mu.RUnlock()
	slices.SortFunc(s.Users, User.Compare)
	return
}

// SnapshotAndReset implements the Collector SnapshotAndReset method.
func (sc *serverCollector) SnapshotAndReset() (s Server) {
	s.Traffic = sc.tc.snapshotAndReset()
	sc.mu.RLock()
	s.Users = make([]User, 0, len(sc.ucs))
	for username, uc := range sc.ucs {
		u := uc.snapshotAndReset(username)
		s.Traffic.Add(u.Traffic)
		s.Users = append(s.Users, u)
	}
	sc.mu.RUnlock()
	slices.SortFunc(s.Users, User.Compare)
	return
}

// Collector collects server traffic statistics.
type Collector interface {
	// CollectTCPSession collects the TCP session's traffic statistics.
	CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64)

	// CollectUDPSessionDownlink collects the UDP session's downlink traffic statistics.
	CollectUDPSessionDownlink(username string, downlinkPackets, downlinkBytes uint64)

	// CollectUDPSessionUplink collects the UDP session's uplink traffic statistics.
	CollectUDPSessionUplink(username string, uplinkPackets, uplinkBytes uint64)

	// Snapshot returns the server's traffic statistics.
	Snapshot() Server

	// SnapshotAndReset returns the server's traffic statistics and resets the statistics.
	SnapshotAndReset() Server
}

// NoopCollector is a no-op collector.
// Its collect methods do nothing and its snapshot method returns empty statistics.
type NoopCollector struct{}

// CollectTCPSession implements the Collector CollectTCPSession method.
func (NoopCollector) CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64) {}

// CollectUDPSessionDownlink implements the Collector CollectUDPSessionDownlink method.
func (NoopCollector) CollectUDPSessionDownlink(username string, downlinkPackets, downlinkBytes uint64) {
}

// CollectUDPSessionUplink implements the Collector CollectUDPSessionUplink method.
func (NoopCollector) CollectUDPSessionUplink(username string, uplinkPackets, uplinkBytes uint64) {}

// Snapshot implements the Collector Snapshot method.
func (NoopCollector) Snapshot() Server {
	return Server{}
}

// SnapshotAndReset implements the Collector SnapshotAndReset method.
func (NoopCollector) SnapshotAndReset() Server {
	return Server{}
}

// Config stores configuration for the stats collector.
type Config struct {
	Enabled bool `json:"enabled"`
}

// Collector returns a new stats collector from the config.
func (c Config) Collector() Collector {
	if c.Enabled {
		return NewServerCollector()
	}
	return NoopCollector{}
}

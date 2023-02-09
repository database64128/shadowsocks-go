package stats

import (
	"sync"
	"sync/atomic"
)

type traffic struct {
	downlinkPackets atomic.Uint64
	downlinkBytes   atomic.Uint64
	uplinkPackets   atomic.Uint64
	uplinkBytes     atomic.Uint64
	tcpSessions     atomic.Uint64
	udpSessions     atomic.Uint64
}

func (t *traffic) collectTCPSession(downlinkBytes, uplinkBytes uint64) {
	t.downlinkBytes.Add(downlinkBytes)
	t.uplinkBytes.Add(uplinkBytes)
	t.tcpSessions.Add(1)
}

func (t *traffic) collectUDPSessionDownlink(downlinkPackets, downlinkBytes uint64) {
	t.downlinkPackets.Add(downlinkPackets)
	t.downlinkBytes.Add(downlinkBytes)
	t.udpSessions.Add(1)
}

func (t *traffic) collectUDPSessionUplink(uplinkPackets, uplinkBytes uint64) {
	t.uplinkPackets.Add(uplinkPackets)
	t.uplinkBytes.Add(uplinkBytes)
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

func (t *traffic) snapshot() Traffic {
	return Traffic{
		DownlinkPackets: t.downlinkPackets.Load(),
		DownlinkBytes:   t.downlinkBytes.Load(),
		UplinkPackets:   t.uplinkPackets.Load(),
		UplinkBytes:     t.uplinkBytes.Load(),
		TCPSessions:     t.tcpSessions.Load(),
		UDPSessions:     t.udpSessions.Load(),
	}
}

type userCollector struct {
	traffic
}

// User stores the user's traffic statistics.
type User struct {
	Name string `json:"username"`
	Traffic
}

func (uc *userCollector) snapshot(username string) User {
	return User{
		Name:    username,
		Traffic: uc.traffic.snapshot(),
	}
}

type serverCollector struct {
	traffic
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

// CollectTCPSession implements the Collector CollectTCPSession method.
func (sc *serverCollector) CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64) {
	sc.userCollector(username).collectTCPSession(downlinkBytes, uplinkBytes)
	sc.collectTCPSession(downlinkBytes, uplinkBytes)
}

// CollectUDPSessionDownlink implements the Collector CollectUDPSessionDownlink method.
func (sc *serverCollector) CollectUDPSessionDownlink(username string, downlinkPackets, downlinkBytes uint64) {
	sc.userCollector(username).collectUDPSessionDownlink(downlinkPackets, downlinkBytes)
	sc.collectUDPSessionDownlink(downlinkPackets, downlinkBytes)
}

// CollectUDPSessionUplink implements the Collector CollectUDPSessionUplink method.
func (sc *serverCollector) CollectUDPSessionUplink(username string, uplinkPackets, uplinkBytes uint64) {
	sc.userCollector(username).collectUDPSessionUplink(uplinkPackets, uplinkBytes)
	sc.collectUDPSessionUplink(uplinkPackets, uplinkBytes)
}

// Server stores the server's traffic statistics.
type Server struct {
	Traffic
	Users []User `json:"users"`
}

// Snapshot implements the Collector Snapshot method.
func (sc *serverCollector) Snapshot() Server {
	sc.mu.RLock()
	users := make([]User, 0, len(sc.ucs))
	for username, uc := range sc.ucs {
		users = append(users, uc.snapshot(username))
	}
	sc.mu.RUnlock()
	return Server{
		Traffic: sc.traffic.snapshot(),
		Users:   users,
	}
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

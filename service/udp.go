package service

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// defaultRelayBatchSize is the default batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	//
	// On an i9-13900K, the average number of messages received in a single recvmmsg(2) call is
	// around 100 in iperf3 tests. Bumping the msgvec size to greater than 256 does not seem to
	// yield any performance improvement.
	//
	// Note that the mainline iperf3 does not use sendmmsg(2) or io_uring for batch sending at the
	// time of writing. So this value is still subject to change in the future.
	defaultRelayBatchSize = 256

	// defaultServerRecvBatchSize is the default batch size of a UDP relay's main receive routine.
	defaultServerRecvBatchSize = 64

	// defaultSendChannelCapacity is the default capacity of a UDP relay session's uplink send channel.
	defaultSendChannelCapacity = 1024

	// defaultNatTimeout is the default duration after which an inactive NAT entry is evicted.
	defaultNatTimeout = 5 * time.Minute
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

// UDPPerfConfig exposes performance tuning parameters for UDP relays.
type UDPPerfConfig struct {
	// BatchMode controls the mode of batch receiving and sending.
	//
	// Available values:
	// - "": Platform default.
	// - "no": Do not receive or send packets in batches.
	// - "sendmmsg": Use recvmmsg(2) and sendmmsg(2) calls. This is the default on Linux and NetBSD.
	BatchMode string `json:"batchMode"`

	// RelayBatchSize is the batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	//
	// The default value is 256.
	RelayBatchSize int `json:"relayBatchSize"`

	// ServerRecvBatchSize is the batch size of a UDP relay's main receive routine.
	//
	// The default value is 64.
	ServerRecvBatchSize int `json:"serverRecvBatchSize"`

	// SendChannelCapacity is the capacity of a UDP relay session's uplink send channel.
	//
	// The default value is 1024.
	SendChannelCapacity int `json:"sendChannelCapacity"`
}

// CheckAndApplyDefaults checks the validity of the configuration and applies default values.
func (c *UDPPerfConfig) CheckAndApplyDefaults() error {
	switch c.BatchMode {
	case "", "no", "sendmmsg":
	default:
		return fmt.Errorf("unknown batch mode: %s", c.BatchMode)
	}

	switch {
	case c.RelayBatchSize > 0 && c.RelayBatchSize <= 1024:
	case c.RelayBatchSize == 0:
		c.RelayBatchSize = defaultRelayBatchSize
	default:
		return fmt.Errorf("relay batch size out of range [0, 1024]: %d", c.RelayBatchSize)
	}

	switch {
	case c.ServerRecvBatchSize > 0 && c.ServerRecvBatchSize <= 1024:
	case c.ServerRecvBatchSize == 0:
		c.ServerRecvBatchSize = defaultServerRecvBatchSize
	default:
		return fmt.Errorf("server recv batch size out of range [0, 1024]: %d", c.ServerRecvBatchSize)
	}

	switch {
	case c.SendChannelCapacity >= 64:
	case c.SendChannelCapacity == 0:
		c.SendChannelCapacity = defaultSendChannelCapacity
	default:
		return fmt.Errorf("send channel capacity must be at least 64: %d", c.SendChannelCapacity)
	}

	return nil
}

// udpRelayServerConn configures the server socket for a UDP relay.
type udpRelayServerConn struct {
	serverConn          *net.UDPConn
	listenConfig        conn.ListenConfig
	network             string
	address             string
	batchMode           string
	relayBatchSize      int
	serverRecvBatchSize int
	sendChannelCapacity int
	natTimeout          time.Duration
}

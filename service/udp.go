package service

import (
	"errors"
	"time"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// defaultRelayBatchSize is the default batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	//
	// On an i5-7400, the average number of messages received in a single recvmmsg(2) call is
	// around 100 in iperf3 tests. Bumping the msgvec size to greater than 256 does not seem to
	// yield any performance improvement.
	//
	// Note that the mainline iperf3 does not use sendmmsg(2) or io_uring for batch sending at the
	// time of writing. So this value is still subject to change in the future.
	defaultRelayBatchSize = 256

	// defaultServerRecvBatchSize is the default batch size of a UDP relay's main receive routine.
	defaultServerRecvBatchSize = 1024

	// defaultSendChannelCapacity is the default capacity of a UDP relay session's uplink send channel.
	defaultSendChannelCapacity = 1024

	// minNatTimeoutSec is the minimum allowed NAT timeout in seconds.
	minNatTimeoutSec = 60

	// defaultNatTimeout is the default duration after which an inactive NAT entry is evicted.
	defaultNatTimeout = 5 * time.Minute
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

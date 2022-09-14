package service

import (
	"errors"
	"time"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// sendChannelCapacity defines NAT entry's send channel capacity.
	sendChannelCapacity = 1024

	// minNatTimeoutSec is the minimum allowed NAT timeout in seconds.
	minNatTimeoutSec = 60

	// defaultNatTimeout is the default duration after which an inactive NAT entry is evicted.
	defaultNatTimeout = 5 * time.Minute

	// defaultRecvmmsgMsgvecSize is the default batch size for recvmmsg(2) and sendmmsg(2) calls.
	//
	// On an i5-7400, the average number of messages received in a single recvmmsg(2) call is
	// around 100 in iperf3 tests. Bumping the msgvec size to greater than 256 does not seem to
	// yield any performance improvement.
	//
	// Note that the mainline iperf3 does not use sendmmsg(2) or io_uring for batch sending at the
	// time of writing. So this value is still subject to change in the future.
	defaultRecvmmsgMsgvecSize = 256
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

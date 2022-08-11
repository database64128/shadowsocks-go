package service

import (
	"errors"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// sendChannelCapacity defines NAT entry's send channel capacity.
	sendChannelCapacity = 1024

	// natTimeout is the duration after which an inactive NAT entry is evicted.
	natTimeout = 5 * time.Minute

	// defaultRecvmmsgMsgvecSize is the default batch size for recvmmsg(2) and sendmmsg(2) calls.
	//
	// In iperf3 tests, the average number of messages received in a single recvmmsg(2) call is
	// around 32. Bumping the msgvec size to greater than 64 does not seem to yield any performance
	// improvement.
	//
	// Note that the mainline iperf3 does not use sendmmsg(2) or io_uring for batch sending at the
	// time of writing. So this value is still subject to change in the future.
	defaultRecvmmsgMsgvecSize = 64
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

// queuedPacket is the structure used by send channels to queue packets for sending.
type queuedPacket struct {
	bufp       *[]byte
	start      int
	length     int
	targetAddr conn.Addr
}

package service

import (
	"errors"
	"time"

	"github.com/database64128/shadowsocks-go/socks5"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// sendChannelCapacity defines NAT entry's send channel capacity.
	sendChannelCapacity = 1024

	// natTimeout is the duration after which an inactive NAT entry is evicted.
	natTimeout = 5 * time.Minute
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

// queuedPacket is the structure used by send channels to queue packets for sending.
type queuedPacket struct {
	bufp       *[]byte
	start      int
	length     int
	targetAddr socks5.Addr
}

//go:build !linux

package service

import (
	"errors"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

func NewUDPTransparentRelay(
	serverName, listenAddress string,
	relayBatchSize, serverRecvBatchSize, sendChannelCapacity, serverIndex, mtu int,
	maxClientPackerHeadroom zerocopy.Headroom,
	natTimeout time.Duration,
	serverConnlistenConfig, transparentConnListenConfig conn.ListenConfig,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) (Relay, error) {
	return nil, errors.New("transparent proxy is not implemented for this platform")
}

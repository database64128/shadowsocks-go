//go:build !linux

package service

import (
	"errors"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"go.uber.org/zap"
)

func NewUDPTransparentRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	transparentConnListenConfig conn.ListenConfig,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) (Relay, error) {
	return nil, errors.New("transparent proxy is not implemented for this platform")
}

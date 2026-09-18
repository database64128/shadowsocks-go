//go:build !linux

package service

import (
	"errors"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/tslog"
)

func NewUDPTransparentRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	transparentConnSocketConfig conn.UDPSocketConfig,
	collector stats.Collector,
	router *router.Router,
	logger *tslog.Logger,
) (shadowsocks.Service, error) {
	return nil, errors.New("transparent proxy is not implemented for this platform")
}

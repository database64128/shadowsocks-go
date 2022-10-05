//go:build !linux

package service

import (
	"errors"
	"time"

	"github.com/database64128/shadowsocks-go/router"
	"go.uber.org/zap"
)

func NewUDPTransparentRelay(
	serverName, listenAddress string,
	batchSize, listenerFwmark, mtu, maxClientFrontHeadroom, maxClientRearHeadroom int,
	natTimeout time.Duration,
	router *router.Router,
	logger *zap.Logger,
) (Relay, error) {
	return nil, errors.New("transparent proxy is not implemented for this platform")
}

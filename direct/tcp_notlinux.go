//go:build !linux

package direct

import (
	"errors"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

func NewTCPTransparentServer() (zerocopy.TCPServer, error) {
	return nil, errors.New("transparent proxy is not implemented for this platform")
}

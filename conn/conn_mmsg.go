//go:build linux || netbsd

package conn

import (
	"context"
	"net"

	"github.com/database64128/tfo-go/v2"
)

// ListenUDPRawConn is like [ListenUDP] but wraps the [*net.UDPConn] in a [rawUDPConn] for batch I/O.
func ListenUDPRawConn(listenConfig tfo.ListenConfig, network, address string) (rawUDPConn, error) {
	packetConn, err := listenConfig.ListenPacket(context.Background(), network, address)
	if err != nil {
		return rawUDPConn{}, err
	}
	return NewRawUDPConn(packetConn.(*net.UDPConn))
}

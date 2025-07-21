//go:build darwin || freebsd || linux || openbsd

package netio

import (
	"fmt"
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
)

// TCPTransparentProxyServer handles tproxy connections.
//
// TCPTransparentProxyServer implements [StreamServer].
type TCPTransparentProxyServer struct{}

func newTCPTransparentProxyServer() (StreamServer, error) {
	return TCPTransparentProxyServer{}, nil
}

// StreamServerInfo implements [StreamServer.StreamServerInfo].
func (TCPTransparentProxyServer) StreamServerInfo() StreamServerInfo {
	return StreamServerInfo{
		NativeInitialPayload: false,
	}
}

// HandleStream implements [StreamServer.HandleStream].
func (TCPTransparentProxyServer) HandleStream(c Conn, _ *zap.Logger) (ConnRequest, error) {
	netAddr := c.LocalAddr()
	tcpAddr, ok := netAddr.(*net.TCPAddr)
	if !ok {
		return ConnRequest{}, fmt.Errorf("LocalAddr is not a *net.TCPAddr: %T", netAddr)
	}
	return ConnRequest{
		PendingConn: NopPendingConn(c),
		Addr:        conn.AddrFromIPPort(tcpAddr.AddrPort()),
	}, nil
}

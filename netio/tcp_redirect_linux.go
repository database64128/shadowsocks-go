package netio

import (
	"fmt"
	"net"
	"syscall"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
)

// TCPRedirectServer handles connections redirected by the netfilter "redirect" statement.
//
// TCPRedirectServer implements [StreamServer].
type TCPRedirectServer struct{}

func newTCPRedirectServer() (StreamServer, error) {
	return TCPRedirectServer{}, nil
}

// StreamServerInfo implements [StreamServer.StreamServerInfo].
func (TCPRedirectServer) StreamServerInfo() StreamServerInfo {
	return StreamServerInfo{
		NativeInitialPayload: false,
	}
}

// HandleStream implements [StreamServer.HandleStream].
func (TCPRedirectServer) HandleStream(c Conn, _ *zap.Logger) (ConnRequest, error) {
	netAddr := c.LocalAddr()
	tcpAddr, ok := netAddr.(*net.TCPAddr)
	if !ok {
		return ConnRequest{}, fmt.Errorf("LocalAddr is not a *net.TCPAddr: %T", netAddr)
	}
	is4 := tcpAddr.AddrPort().Addr().Is4()

	sc, ok := c.(syscall.Conn)
	if !ok {
		return ConnRequest{}, fmt.Errorf("connection does not implement syscall.Conn: %T", c)
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return ConnRequest{}, err
	}

	addrPort, err := conn.GetRedirectOriginalDst(rawConn, is4)
	if err != nil {
		return ConnRequest{}, err
	}
	return ConnRequest{
		PendingConn: NopPendingConn(c),
		Addr:        conn.AddrFromIPPort(addrPort),
	}, nil
}

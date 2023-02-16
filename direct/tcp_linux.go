package direct

import (
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPTransparentServer is a transparent proxy server.
//
// TCPTransparentServer implements the zerocopy TCPServer interface.
type TCPTransparentServer struct{}

func NewTCPTransparentServer() (zerocopy.TCPServer, error) {
	return TCPTransparentServer{}, nil
}

// Info implements the zerocopy.TCPServer Info method.
func (TCPTransparentServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (TCPTransparentServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	tc, ok := rawRW.(*net.TCPConn)
	if !ok {
		return nil, conn.Addr{}, nil, "", zerocopy.ErrAcceptRequiresTCPConn
	}
	return &DirectStreamReadWriter{rw: rawRW}, conn.AddrFromIPPort(tc.LocalAddr().(*net.TCPAddr).AddrPort()), nil, "", nil
}

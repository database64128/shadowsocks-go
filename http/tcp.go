package http

import (
	"context"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// ProxyClient implements the zerocopy TCPClient interface.
type ProxyClient struct {
	name    string
	address string
	dialer  conn.Dialer
}

func NewProxyClient(name, address string, dialer conn.Dialer) *ProxyClient {
	return &ProxyClient{
		name:    name,
		address: address,
		dialer:  dialer,
	}
}

// Info implements the zerocopy.TCPClient Info method.
func (c *ProxyClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: false,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ProxyClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	rawRW, err = c.dialer.DialTCP(ctx, "tcp", c.address, nil)
	if err != nil {
		return
	}

	rw, err = NewHttpStreamClientReadWriter(rawRW, targetAddr)
	if err != nil {
		rawRW.Close()
		return
	}

	if len(payload) > 0 {
		if _, err = rw.WriteZeroCopy(payload, 0, len(payload)); err != nil {
			rawRW.Close()
		}
	}
	return
}

// ProxyServer implements the zerocopy TCPServer interface.
type ProxyServer struct {
	logger *zap.Logger
}

func NewProxyServer(logger *zap.Logger) *ProxyServer {
	return &ProxyServer{logger}
}

// Info implements the zerocopy.TCPServer Info method.
func (s *ProxyServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *ProxyServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewHttpStreamServerReadWriter(rawRW, s.logger)
	return
}

package http

import (
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
)

// ProxyClient implements the zerocopy TCPClient interface.
type ProxyClient struct {
	address string
	dialer  tfo.Dialer
}

func NewProxyClient(address string, dialerTFO bool, dialerFwmark int) *ProxyClient {
	return &ProxyClient{
		address: address,
		dialer:  conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ProxyClient) Dial(targetAddr socks5.Addr, payload []byte) (zerocopy.ReadWriter, error) {
	conn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return nil, err
	}

	return NewHttpStreamClientReadWriter(conn.(tfo.Conn), targetAddr)
}

// ProxyServer implements the zerocopy TCPServer interface.
type ProxyServer struct {
	logger *zap.Logger
}

func NewProxyServer(logger *zap.Logger) *ProxyServer {
	return &ProxyServer{logger}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *ProxyServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewHttpStreamServerReadWriter(conn, s.logger)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *ProxyServer) NativeInitialPayload() bool {
	return false
}

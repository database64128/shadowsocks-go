package http

import (
	"github.com/database64128/shadowsocks-go/conn"
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
func (c *ProxyClient) Dial(targetAddr conn.Addr, payload []byte) (tfoConn tfo.Conn, rw zerocopy.ReadWriter, err error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return
	}
	tfoConn = netConn.(tfo.Conn)

	rw, err = NewHttpStreamClientReadWriter(tfoConn, targetAddr)
	if err != nil {
		return
	}

	if len(payload) > 0 {
		_, err = rw.WriteZeroCopy(payload, 0, len(payload))
	}
	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *ProxyClient) NativeInitialPayload() bool {
	return false
}

// ProxyServer implements the zerocopy TCPServer interface.
type ProxyServer struct {
	logger *zap.Logger
}

func NewProxyServer(logger *zap.Logger) *ProxyServer {
	return &ProxyServer{logger}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *ProxyServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewHttpStreamServerReadWriter(conn, s.logger)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *ProxyServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *ProxyServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return nil
}

package http

import (
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
	"go.uber.org/zap"
)

// ProxyClient implements the zerocopy TCPClient interface.
type ProxyClient struct {
	name    string
	address string
	dialer  tfo.Dialer
}

func NewProxyClient(name, address string, dialerTFO bool, dialerFwmark int) *ProxyClient {
	return &ProxyClient{
		name:    name,
		address: address,
		dialer:  conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// String implements the zerocopy.TCPClient String method.
func (c *ProxyClient) String() string {
	return c.name
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ProxyClient) Dial(targetAddr conn.Addr, payload []byte) (tc *net.TCPConn, rw zerocopy.ReadWriter, err error) {
	nc, err := c.dialer.Dial("tcp", c.address, nil)
	if err != nil {
		return
	}
	tc = nc.(*net.TCPConn)

	rw, err = NewHttpStreamClientReadWriter(tc, targetAddr)
	if err != nil {
		tc.Close()
		return
	}

	if len(payload) > 0 {
		if _, err = rw.WriteZeroCopy(payload, 0, len(payload)); err != nil {
			tc.Close()
		}
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
func (s *ProxyServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewHttpStreamServerReadWriter(rawRW, s.logger)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *ProxyServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *ProxyServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.JustClose
}

package netio

import (
	"context"

	"github.com/database64128/shadowsocks-go/conn"
)

// TCPClient opens TCP connections and returns them directly.
//
// TCPClient implements [StreamClient] and [StreamDialer].
type TCPClient struct {
	name    string
	network string
	dialer  conn.Dialer
}

var (
	_ StreamClient = (*TCPClient)(nil)
	_ StreamDialer = (*TCPClient)(nil)
)

// NewTCPClient returns a new TCP client.
func NewTCPClient(name, network string, dialer conn.Dialer) *TCPClient {
	return &TCPClient{
		name:    name,
		network: network,
		dialer:  dialer,
	}
}

// NewStreamDialer implements [StreamClient.NewStreamDialer].
func (c *TCPClient) NewStreamDialer() (StreamDialer, StreamDialerInfo) {
	return c, StreamDialerInfo{
		Name:                 c.name,
		NativeInitialPayload: !c.dialer.DisableTFO,
	}
}

// DialStream implements [StreamDialer.DialStream].
func (c *TCPClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (Conn, error) {
	return c.dialer.DialTCP(ctx, c.network, addr.String(), payload)
}

// NewTCPTransparentProxyServer returns a new TCP transparent proxy server.
func NewTCPTransparentProxyServer() (StreamServer, error) {
	return newTCPTransparentProxyServer()
}

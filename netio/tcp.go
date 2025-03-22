package netio

import (
	"context"

	"github.com/database64128/shadowsocks-go/conn"
)

// TCPClientConfig is the configuration for a TCP client.
type TCPClientConfig struct {
	// Name is the name of the client.
	Name string

	// Network controls the address family when resolving domain name destination addresses.
	//
	// - "tcp": System default, likely dual-stack.
	// - "tcp4": Resolve to IPv4 addresses.
	// - "tcp6": Resolve to IPv6 addresses.
	Network string

	// Dialer is the dialer used to establish connections.
	Dialer conn.Dialer
}

// NewTCPClient returns a new TCP client.
func (c *TCPClientConfig) NewTCPClient() *TCPClient {
	return &TCPClient{
		name:    c.Name,
		network: c.Network,
		dialer:  c.Dialer,
	}
}

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

package ssnone

import (
	"context"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/socks5"
	"go.uber.org/zap"
)

// StreamClientConfig is the configuration for a Shadowsocks "none" stream client.
type StreamClientConfig struct {
	// Name is the name of the client.
	Name string

	// InnerClient is the underlying stream client.
	InnerClient netio.StreamClient

	// Addr is the address of the Shadowsocks "none" server.
	Addr conn.Addr
}

// NewStreamClient returns a new Shadowsocks "none" stream client.
func (c *StreamClientConfig) NewStreamClient() *StreamClient {
	return &StreamClient{
		name:        c.Name,
		innerClient: c.InnerClient,
		serverAddr:  c.Addr,
	}
}

// StreamClient is a Shadowsocks "none" stream client.
//
// StreamClient implements [netio.StreamClient] and [netio.StreamDialer].
type StreamClient struct {
	name        string
	innerClient netio.StreamClient
	serverAddr  conn.Addr
}

var (
	_ netio.StreamClient = (*StreamClient)(nil)
	_ netio.StreamDialer = (*StreamClient)(nil)
)

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (c *StreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, netio.StreamDialerInfo{
		Name:                 c.name,
		NativeInitialPayload: true,
	}
}

// DialStream implements [netio.StreamDialer.DialStream].
func (c *StreamClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (netio.Conn, error) {
	addrLen := socks5.LengthOfAddrFromConnAddr(addr)
	b := make([]byte, addrLen+len(payload))
	_ = socks5.WriteAddrFromConnAddr(b, addr)
	_ = copy(b[addrLen:], payload)
	return c.innerClient.DialStream(ctx, c.serverAddr, b)
}

// StreamServer is a Shadowsocks "none" stream server.
//
// The zero value is ready for use.
//
// StreamServer implements [netio.StreamServer].
type StreamServer struct{}

var _ netio.StreamServer = StreamServer{}

// StreamServerInfo implements [netio.StreamServer.StreamServerInfo].
func (StreamServer) StreamServerInfo() netio.StreamServerInfo {
	return netio.StreamServerInfo{
		NativeInitialPayload: false,
	}
}

// HandleStream implements [netio.StreamServer.HandleStream].
func (StreamServer) HandleStream(c netio.Conn, _ *zap.Logger) (netio.ConnRequest, error) {
	addr, err := socks5.ConnAddrFromReader(c)
	if err != nil {
		return netio.ConnRequest{}, err
	}
	return netio.ConnRequest{
		PendingConn: netio.NopPendingConn(c),
		Addr:        addr,
	}, nil
}

// Package tlsproxy provides the TLS termination proxy implementation.
package tlsproxy

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/tslog"
)

// ProxyClient is a TLS termination proxy client.
//
// ProxyClient implements [netio.StreamClient] and [netio.StreamDialer].
type ProxyClient struct {
	name        string
	innerClient netio.StreamClient
	tlsConfig   *tls.Config
}

var (
	_ netio.StreamClient = (*ProxyClient)(nil)
	_ netio.StreamDialer = (*ProxyClient)(nil)
)

// NewProxyClient creates a new TLS termination proxy client.
func NewProxyClient(name string, innerClient netio.StreamClient, tlsConfig *tls.Config) *ProxyClient {
	return &ProxyClient{
		name:        name,
		innerClient: innerClient,
		tlsConfig:   tlsConfig,
	}
}

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (c *ProxyClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, netio.StreamDialerInfo{
		Name:                 c.name,
		NativeInitialPayload: false,
	}
}

// DialStream implements [netio.StreamDialer.DialStream].
func (c *ProxyClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (netio.Conn, error) {
	innerConn, err := c.innerClient.DialStream(ctx, addr, nil)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(innerConn, c.tlsConfig)

	if err := netio.ConnReadWriteContextFunc(ctx, innerConn, func(innerConn netio.Conn) error {
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("failed to complete TLS handshake: %w", err)
		}

		if len(payload) > 0 {
			if _, err := tlsConn.Write(payload); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		_ = innerConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// ProxyServer is a TLS termination proxy server.
//
// ProxyServer implements [netio.StreamServer].
type ProxyServer struct {
	innerServer netio.StreamServer
	tlsConfig   *tls.Config
}

var _ netio.StreamServer = (*ProxyServer)(nil)

// NewProxyServer creates a new TLS termination proxy server.
func NewProxyServer(innerServer netio.StreamServer, tlsConfig *tls.Config) *ProxyServer {
	return &ProxyServer{
		innerServer: innerServer,
		tlsConfig:   tlsConfig,
	}
}

// StreamServerInfo implements [netio.StreamServer.StreamServerInfo].
func (s *ProxyServer) StreamServerInfo() netio.StreamServerInfo {
	return s.innerServer.StreamServerInfo()
}

// HandleStream implements [netio.StreamServer.HandleStream].
func (s *ProxyServer) HandleStream(c netio.Conn, logger *tslog.Logger) (netio.ConnRequest, error) {
	tlsConn := tls.Server(c, s.tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return netio.ConnRequest{}, fmt.Errorf("failed to complete TLS handshake: %w", err)
	}

	req, err := s.innerServer.HandleStream(tlsConn, logger)
	if err != nil {
		_ = tlsConn.Close()
		return netio.ConnRequest{}, err
	}

	if req.Username == "" {
		if verifiedChains := tlsConn.ConnectionState().VerifiedChains; len(verifiedChains) > 0 {
			if firstChain := verifiedChains[0]; len(firstChain) > 0 {
				req.Username = firstChain[0].Subject.CommonName
			}
		}
	}

	return req, nil
}

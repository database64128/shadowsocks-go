package http

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

var errUsernameContainsColon = errors.New("username contains colon")

// ClientConfig contains configuration options for an HTTP proxy client.
type ClientConfig struct {
	// Name is the name of the client.
	Name string

	// Network controls the address family when resolving the address.
	//
	// - "tcp": System default, likely dual-stack.
	// - "tcp4": Resolve to IPv4 addresses.
	// - "tcp6": Resolve to IPv6 addresses.
	Network string

	// Address is the address of the remote proxy server.
	Address string

	// Dialer is the dialer used to establish connections.
	Dialer conn.Dialer

	// Username is the username used for authentication.
	Username string

	// Password is the password used for authentication.
	Password string

	// UseBasicAuth controls whether to use HTTP Basic Authentication.
	UseBasicAuth bool
}

// ProxyClient implements the zerocopy TCPClient interface.
type ProxyClient struct {
	name    string
	network string
	address string
	dialer  conn.Dialer

	proxyAuthHeader string
}

// NewProxyClient creates a new HTTP proxy client.
func (c *ClientConfig) NewProxyClient() (*ProxyClient, error) {
	client := ProxyClient{
		name:    c.Name,
		network: c.Network,
		address: c.Address,
		dialer:  c.Dialer,
	}

	if c.UseBasicAuth {
		if strings.IndexByte(c.Username, ':') >= 0 {
			return nil, errUsernameContainsColon
		}

		const proxyAuthHeaderPrefix = "\r\nProxy-Authorization: Basic "
		length := len(proxyAuthHeaderPrefix) + base64.StdEncoding.EncodedLen(len(c.Username)+1+len(c.Password))
		b := make([]byte, length)
		_ = copy(b, proxyAuthHeaderPrefix)
		base64.StdEncoding.Encode(b[len(proxyAuthHeaderPrefix):], []byte(c.Username+":"+c.Password))
		client.proxyAuthHeader = unsafe.String(unsafe.SliceData(b), length)
	}

	return &client, nil
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
	rawRW, err = c.dialer.DialTCP(ctx, c.network, c.address, nil)
	if err != nil {
		return
	}

	rw, err = NewHttpStreamClientReadWriter(rawRW, targetAddr, c.proxyAuthHeader)
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

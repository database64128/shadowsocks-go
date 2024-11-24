package http

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
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

// ProxyClient is an HTTP proxy client.
//
// ProxyClient implements [zerocopy.TCPClient].
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

// Info implements [zerocopy.TCPClient.Info].
func (c *ProxyClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: false,
	}
}

// Dial implements [zerocopy.TCPClient.Dial].
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

// ServerConfig contains configuration options for an HTTP proxy server.
type ServerConfig struct {
	// Logger is the logger used for logging.
	Logger *zap.Logger

	// Users is a list of users allowed to connect to the server.
	// It is ignored if none of the authentication methods are enabled.
	Users []ServerUserCredentials

	// EnableBasicAuth controls whether to enable HTTP Basic Authentication.
	EnableBasicAuth bool
}

// ServerUserCredentials contains the username and password for a server user.
type ServerUserCredentials struct {
	// Username is the username.
	Username string `json:"username"`

	// Password is the password.
	Password string `json:"password"`
}

// ProxyServer is an HTTP proxy server.
//
// ProxyServer implements [zerocopy.TCPServer].
type ProxyServer struct {
	logger          *zap.Logger
	usernameByToken map[string]string
}

// NewProxyServer creates a new HTTP proxy server.
func (c *ServerConfig) NewProxyServer() (*ProxyServer, error) {
	server := ProxyServer{
		logger: c.Logger,
	}

	if c.EnableBasicAuth {
		var b []byte
		server.usernameByToken = make(map[string]string, len(c.Users))
		for _, user := range c.Users {
			if strings.IndexByte(user.Username, ':') >= 0 {
				return nil, errUsernameContainsColon
			}

			b = b[:0]
			b = slices.Grow(b, len(user.Username)+1+len(user.Password))
			b = append(b, user.Username...)
			b = append(b, ':')
			b = append(b, user.Password...)
			token := base64.StdEncoding.EncodeToString(b)
			server.usernameByToken[token] = user.Username
		}
	}

	return &server, nil
}

// Info implements [zerocopy.TCPServer.Info].
func (s *ProxyServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements [zerocopy.TCPServer.Accept].
func (s *ProxyServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, username, err = NewHttpStreamServerReadWriter(rawRW, s.usernameByToken, s.logger)
	return
}

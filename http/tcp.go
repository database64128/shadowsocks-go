package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
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

	// Certificates is an optional list of client certificates for mutual TLS.
	// See [tls.Config.Certificates].
	Certificates []tls.Certificate

	// GetClientCertificate is an optional function that returns the client certificate for mutual TLS.
	// See [tls.Config.GetClientCertificate].
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	// RootCAs is the set of root CAs used to verify server certificates.
	// If nil, the host's CA set is used.
	// See [tls.Config.RootCAs].
	RootCAs *x509.CertPool

	// ServerName is the server name used to verify the hostname on the returned certificates.
	// See [tls.Config.ServerName].
	ServerName string

	// EncryptedClientHelloConfigList is a serialized ECHConfigList.
	// See [tls.Config.EncryptedClientHelloConfigList].
	EncryptedClientHelloConfigList []byte

	// Username is the username used for authentication.
	Username string

	// Password is the password used for authentication.
	Password string

	// UseTLS controls whether to use TLS.
	UseTLS bool

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

	tlsConfig *tls.Config

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

	if c.UseTLS {
		client.tlsConfig = &tls.Config{
			Certificates:                   c.Certificates,
			GetClientCertificate:           c.GetClientCertificate,
			RootCAs:                        c.RootCAs,
			ServerName:                     c.ServerName,
			EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		}
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
	tcpConn, err := c.dialer.DialTCP(ctx, c.network, c.address, nil)
	if err != nil {
		return nil, nil, err
	}

	if c.tlsConfig != nil {
		tlsConn := tls.Client(tcpConn, c.tlsConfig)
		rawRW = directReadWriteCloserFromTLSConn(tlsConn)
	} else {
		rawRW = tcpConn
	}

	rw, err = NewHttpStreamClientReadWriter(rawRW, targetAddr, c.proxyAuthHeader)
	if err != nil {
		_ = rawRW.Close()
		return nil, nil, err
	}

	if len(payload) > 0 {
		if _, err = rw.WriteZeroCopy(payload, 0, len(payload)); err != nil {
			_ = rawRW.Close()
			return nil, nil, err
		}
	}

	return rawRW, rw, nil
}

// ServerConfig contains configuration options for an HTTP proxy server.
type ServerConfig struct {
	// Logger is the logger used for logging.
	Logger *zap.Logger

	// Users is a list of users allowed to connect to the server.
	// It is ignored if none of the authentication methods are enabled.
	Users []ServerUserCredentials

	// Certificates is the list of server certificates for TLS.
	// See [tls.Config.Certificates].
	Certificates []tls.Certificate

	// GetCertificate is a function that returns the server certificate for TLS.
	// See [tls.Config.GetCertificate].
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// ClientCAs is the set of root CAs used to verify client certificates.
	// See [tls.Config.ClientCAs].
	ClientCAs *x509.CertPool

	// EnableBasicAuth controls whether to enable HTTP Basic Authentication.
	EnableBasicAuth bool

	// EnableTLS controls whether to enable TLS.
	EnableTLS bool

	// RequireAndVerifyClientCert controls whether to require and verify client certificates.
	RequireAndVerifyClientCert bool
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
func (c *ServerConfig) NewProxyServer() (zerocopy.TCPServer, error) {
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

	if c.EnableTLS {
		tlsServer := TLSProxyServer{
			plainServer: server,
			tlsConfig: &tls.Config{
				Certificates:   c.Certificates,
				GetCertificate: c.GetCertificate,
				ClientCAs:      c.ClientCAs,
			},
		}
		if c.RequireAndVerifyClientCert {
			tlsServer.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		return &tlsServer, nil
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

// TLSProxyServer is an HTTP proxy server that uses TLS.
//
// TLSProxyServer implements [zerocopy.TCPServer].
type TLSProxyServer struct {
	plainServer ProxyServer
	tlsConfig   *tls.Config
}

// Info implements [zerocopy.TCPServer.Info].
func (s *TLSProxyServer) Info() zerocopy.TCPServerInfo {
	return s.plainServer.Info()
}

// Accept implements [zerocopy.TCPServer.Accept].
func (s *TLSProxyServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	netConn, ok := rawRW.(net.Conn)
	if !ok {
		return nil, conn.Addr{}, nil, "", zerocopy.ErrAcceptRequiresNetConn
	}

	tlsConn := tls.Server(netConn, s.tlsConfig)
	rawRW = directReadWriteCloserFromTLSConn(tlsConn)
	rw, targetAddr, payload, username, err = s.plainServer.Accept(rawRW)
	if err != nil {
		return
	}

	if s.plainServer.usernameByToken == nil && s.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		tlsConnState := tlsConn.ConnectionState()
		username = tlsConnState.PeerCertificates[0].Subject.CommonName
	}

	return
}

// tlsConnDirectReadWriteCloser wraps a [*tls.Conn] as a [zerocopy.DirectReadWriteCloser]
// by adding a no-op [CloseRead] method.
//
// [tls.Conn.CloseWrite] does not call the underlying connection's CloseWrite method.
// Nevertheless, it sends an alertCloseNotify record, which causes Read on the other end to return [io.EOF].
type tlsConnDirectReadWriteCloser struct {
	*tls.Conn
}

// directReadWriteCloserFromTLSConn creates a [zerocopy.DirectReadWriteCloser] from a [*tls.Conn].
func directReadWriteCloserFromTLSConn(c *tls.Conn) zerocopy.DirectReadWriteCloser {
	return tlsConnDirectReadWriteCloser{c}
}

// CloseRead implements [zerocopy.DirectReadWriteCloser.CloseRead].
func (tlsConnDirectReadWriteCloser) CloseRead() error {
	return nil
}

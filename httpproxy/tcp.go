package httpproxy

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
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

var errUsernameContainsColon = errors.New("username contains colon")

// ClientConfig contains configuration options for an HTTP proxy client.
type ClientConfig struct {
	// Name is the name of the client.
	Name string

	// InnerClient is the underlying stream client.
	InnerClient netio.StreamClient

	// Addr is the address of the HTTP proxy server.
	Addr conn.Addr

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
// ProxyClient implements [zerocopy.TCPClient] and [zerocopy.TCPDialer].
type ProxyClient struct {
	name        string
	innerClient netio.StreamClient
	serverAddr  conn.Addr

	tlsConfig *tls.Config

	proxyAuthHeader string
}

// NewProxyClient creates a new HTTP proxy client.
func (c *ClientConfig) NewProxyClient() (*ProxyClient, error) {
	client := ProxyClient{
		name:        c.Name,
		innerClient: c.InnerClient,
		serverAddr:  c.Addr,
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

// NewDialer implements [zerocopy.TCPClient.NewDialer].
func (c *ProxyClient) NewDialer() (zerocopy.TCPDialer, zerocopy.TCPClientInfo) {
	return c, zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: false,
	}
}

// Dial implements [zerocopy.TCPDialer.Dial].
func (c *ProxyClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	innerConn, err := c.innerClient.DialStream(ctx, c.serverAddr, nil)
	if err != nil {
		return nil, nil, err
	}

	if c.tlsConfig != nil {
		innerConn = tls.Client(innerConn, c.tlsConfig)
	}

	var clientConn netio.Conn

	if err = netio.ConnWriteContextFunc(ctx, innerConn, func(innerConn netio.Conn) (err error) {
		clientConn, err = ClientConnect(innerConn, targetAddr, c.proxyAuthHeader)
		if err != nil {
			return err
		}

		if len(payload) > 0 {
			if _, err = clientConn.Write(payload); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		_ = innerConn.Close()
		return nil, nil, err
	}

	return innerConn, direct.NewDirectStreamReadWriter(clientConn), nil
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

	// EncryptedClientHelloKeys are the ECH keys to use when a client attempts ECH.
	// See [tls.Config.EncryptedClientHelloKeys].
	EncryptedClientHelloKeys []EncryptedClientHelloKey

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

// EncryptedClientHelloKey holds a private key that is associated
// with a specific ECH config known to a client.
type EncryptedClientHelloKey struct {
	// Config should be a marshalled ECHConfig associated with PrivateKey. This
	// must match the config provided to clients byte-for-byte. The config
	// should only specify the DHKEM(X25519, HKDF-SHA256) KEM ID (0x0020), the
	// HKDF-SHA256 KDF ID (0x0001), and a subset of the following AEAD IDs:
	// AES-128-GCM (0x0000), AES-256-GCM (0x0001), ChaCha20Poly1305 (0x0002).
	Config []byte `json:"config"`

	// PrivateKey should be a marshalled private key. Currently, we expect
	// this to be the output of [ecdh.PrivateKey.Bytes].
	PrivateKey []byte `json:"privateKey"`

	// SendAsRetry indicates if Config should be sent as part of the list of
	// retry configs when ECH is requested by the client but rejected by the
	// server.
	SendAsRetry bool `json:"sendAsRetry"`
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
		echKeys := make([]tls.EncryptedClientHelloKey, len(c.EncryptedClientHelloKeys))
		for i, key := range c.EncryptedClientHelloKeys {
			echKeys[i] = tls.EncryptedClientHelloKey{
				Config:      key.Config,
				PrivateKey:  key.PrivateKey,
				SendAsRetry: key.SendAsRetry,
			}
		}
		tlsServer := TLSProxyServer{
			plainServer: server,
			tlsConfig: &tls.Config{
				Certificates:             c.Certificates,
				GetCertificate:           c.GetCertificate,
				ClientCAs:                c.ClientCAs,
				EncryptedClientHelloKeys: echKeys,
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
	pc, targetAddr, username, err := ServerHandle(rawRW.(netio.Conn), s.logger, s.usernameByToken)
	if err != nil {
		return nil, conn.Addr{}, nil, "", err
	}
	c, err := pc.Proceed()
	if err != nil {
		return nil, conn.Addr{}, nil, "", err
	}
	return direct.NewDirectStreamReadWriter(c), targetAddr, nil, username, nil
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
	rw, targetAddr, payload, username, err = s.plainServer.Accept(tlsConn)
	if err != nil {
		return
	}

	if s.plainServer.usernameByToken == nil && s.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		tlsConnState := tlsConn.ConnectionState()
		username = tlsConnState.PeerCertificates[0].Subject.CommonName
	}

	return
}

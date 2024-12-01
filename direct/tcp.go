package direct

import (
	"context"
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	name    string
	network string
	dialer  conn.Dialer
}

func NewTCPClient(name, network string, dialer conn.Dialer) *TCPClient {
	return &TCPClient{
		name:    name,
		network: network,
		dialer:  dialer,
	}
}

// Info implements the zerocopy.TCPClient Info method.
func (c *TCPClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: !c.dialer.DisableTFO,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	rawRW, err = c.dialer.DialTCP(ctx, c.network, targetAddr.String(), payload)
	if err != nil {
		return
	}
	rw = &DirectStreamReadWriter{rw: rawRW}
	return
}

// TCPServer is the client-side tunnel server.
//
// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	targetAddr conn.Addr
}

func NewTCPServer(targetAddr conn.Addr) *TCPServer {
	return &TCPServer{
		targetAddr: targetAddr,
	}
}

// Info implements the zerocopy.TCPServer Info method.
func (s *TCPServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	return &DirectStreamReadWriter{rw: rawRW}, s.targetAddr, nil, "", nil
}

// ShadowsocksNoneTCPClient implements the zerocopy TCPClient interface.
type ShadowsocksNoneTCPClient struct {
	name string
	tco  *zerocopy.TCPConnOpener
}

func NewShadowsocksNoneTCPClient(name, network, address string, dialer conn.Dialer) *ShadowsocksNoneTCPClient {
	return &ShadowsocksNoneTCPClient{
		name: name,
		tco:  zerocopy.NewTCPConnOpener(dialer, network, address),
	}
}

// Info implements the zerocopy.TCPClient Info method.
func (c *ShadowsocksNoneTCPClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: true,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ShadowsocksNoneTCPClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	rw, rawRW, err = NewShadowsocksNoneStreamClientReadWriter(ctx, c.tco, targetAddr, payload)
	return
}

// ShadowsocksNoneTCPServer implements the zerocopy TCPServer interface.
type ShadowsocksNoneTCPServer struct{}

func NewShadowsocksNoneTCPServer() ShadowsocksNoneTCPServer {
	return ShadowsocksNoneTCPServer{}
}

// Info implements the zerocopy.TCPServer Info method.
func (ShadowsocksNoneTCPServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (ShadowsocksNoneTCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewShadowsocksNoneStreamServerReadWriter(rawRW)
	return
}

// Socks5TCPClient implements the zerocopy TCPClient interface.
type Socks5TCPClient struct {
	name    string
	network string
	address string
	dialer  conn.Dialer
}

func NewSocks5TCPClient(name, network, address string, dialer conn.Dialer) *Socks5TCPClient {
	return &Socks5TCPClient{
		name:    name,
		network: network,
		address: address,
		dialer:  dialer,
	}
}

// Info implements the zerocopy.TCPClient Info method.
func (c *Socks5TCPClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: false,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *Socks5TCPClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	rawRW, err = c.dialer.DialTCP(ctx, c.network, c.address, nil)
	if err != nil {
		return
	}

	rw, err = NewSocks5StreamClientReadWriter(rawRW, targetAddr)
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

// Socks5TCPServerConfig contains configuration options for a SOCKS5 TCP server.
type Socks5TCPServerConfig struct {
	// Users is a list of users allowed to connect to the server.
	// It is ignored if none of the authentication methods are enabled.
	Users []socks5.UserInfo

	// EnableUserPassAuth controls whether to enable username/password authentication.
	EnableUserPassAuth bool

	// EnableTCP controls whether to accept CONNECT requests.
	EnableTCP bool

	// EnableUDP controls whether to accept UDP ASSOCIATE requests.
	EnableUDP bool
}

// NewServer creates a new SOCKS5 TCP server.
func (c *Socks5TCPServerConfig) NewServer() (zerocopy.TCPServer, error) {
	server := Socks5TCPServer{
		enableTCP: c.EnableTCP,
		enableUDP: c.EnableUDP,
	}

	if c.EnableUserPassAuth {
		userInfoByUsername := make(map[string]socks5.UserInfo, len(c.Users))

		for i, u := range c.Users {
			if err := u.Validate(); err != nil {
				return nil, fmt.Errorf("bad user credentials at index %d: %w", i, err)
			}
			userInfoByUsername[u.Username] = u
		}

		return &Socks5AuthTCPServer{
			userInfoByUsername: userInfoByUsername,
			plainServer:        server,
		}, nil
	}

	return &server, nil
}

// Socks5TCPServer is an unauthenticated SOCKS5 TCP server.
//
// Socks5TCPServer implements [zerocopy.TCPServer].
type Socks5TCPServer struct {
	enableTCP bool
	enableUDP bool
}

// Info implements [zerocopy.TCPServer.Info].
func (*Socks5TCPServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements [zerocopy.TCPServer.Accept].
func (s *Socks5TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(rawRW, s.enableTCP, s.enableUDP)
	if err == socks5.ErrUDPAssociateDone {
		err = zerocopy.ErrAcceptDoneNoRelay
	}
	return
}

// Socks5AuthTCPServer is like [Socks5TCPServer], but uses username/password authentication.
//
// Socks5AuthTCPServer implements [zerocopy.TCPServer].
type Socks5AuthTCPServer struct {
	userInfoByUsername map[string]socks5.UserInfo
	plainServer        Socks5TCPServer
}

// Info implements [zerocopy.TCPServer.Info].
func (s *Socks5AuthTCPServer) Info() zerocopy.TCPServerInfo {
	return s.plainServer.Info()
}

// Accept implements [zerocopy.TCPServer.Accept].
func (s *Socks5AuthTCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, username, err = NewSocks5AuthStreamServerReadWriter(rawRW, s.userInfoByUsername, s.plainServer.enableTCP, s.plainServer.enableUDP)
	if err == socks5.ErrUDPAssociateDone {
		err = zerocopy.ErrAcceptDoneNoRelay
	}
	return
}

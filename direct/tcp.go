package direct

import (
	"context"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	name   string
	dialer conn.Dialer
}

func NewTCPClient(name string, dialer conn.Dialer) *TCPClient {
	return &TCPClient{
		name:   name,
		dialer: dialer,
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
	rawRW, err = c.dialer.DialTCP(ctx, "tcp", targetAddr.String(), payload)
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

func NewShadowsocksNoneTCPClient(name, address string, dialer conn.Dialer) *ShadowsocksNoneTCPClient {
	return &ShadowsocksNoneTCPClient{
		name: name,
		tco:  zerocopy.NewTCPConnOpener(dialer, "tcp", address),
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
	address string
	dialer  conn.Dialer
}

func NewSocks5TCPClient(name, address string, dialer conn.Dialer) *Socks5TCPClient {
	return &Socks5TCPClient{
		name:    name,
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
	rawRW, err = c.dialer.DialTCP(ctx, "tcp", c.address, nil)
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

// Socks5TCPServer implements the zerocopy TCPServer interface.
type Socks5TCPServer struct {
	enableTCP bool
	enableUDP bool
}

func NewSocks5TCPServer(enableTCP, enableUDP bool) *Socks5TCPServer {
	return &Socks5TCPServer{
		enableTCP: enableTCP,
		enableUDP: enableUDP,
	}
}

// Info implements the zerocopy.TCPServer Info method.
func (s *Socks5TCPServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: false,
		DefaultTCPConnCloser: zerocopy.JustClose,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *Socks5TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(rawRW, s.enableTCP, s.enableUDP)
	if err == socks5.ErrUDPAssociateDone {
		err = zerocopy.ErrAcceptDoneNoRelay
	}
	return
}

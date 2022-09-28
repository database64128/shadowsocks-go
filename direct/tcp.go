package direct

import (
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	dialer tfo.Dialer
}

func NewTCPClient(dialerTFO bool, dialerFwmark int) *TCPClient {
	return &TCPClient{
		dialer: conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr conn.Addr, payload []byte) (tc *net.TCPConn, rw zerocopy.ReadWriter, err error) {
	nc, err := c.dialer.Dial("tcp", targetAddr.String(), payload)
	if err != nil {
		return
	}
	tc = nc.(*net.TCPConn)
	rw = &DirectStreamReadWriter{rw: tc}
	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *TCPClient) NativeInitialPayload() bool {
	return !c.dialer.DisableTFO
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

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(tc *net.TCPConn) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	return &DirectStreamReadWriter{
		rw: tc,
	}, s.targetAddr, nil, nil
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *TCPServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.JustClose
}

// ShadowsocksNoneTCPClient implements the zerocopy TCPClient interface.
type ShadowsocksNoneTCPClient struct {
	tco *zerocopy.TCPConnOpener
}

func NewShadowsocksNoneTCPClient(address string, dialerTFO bool, dialerFwmark int) *ShadowsocksNoneTCPClient {
	return &ShadowsocksNoneTCPClient{
		tco: zerocopy.NewTCPConnOpener(conn.NewDialer(dialerTFO, dialerFwmark), "tcp", address),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ShadowsocksNoneTCPClient) Dial(targetAddr conn.Addr, payload []byte) (tc *net.TCPConn, rw zerocopy.ReadWriter, err error) {
	rw, rawRW, err := NewShadowsocksNoneStreamClientReadWriter(c.tco, targetAddr, payload)
	if err == nil {
		tc = rawRW.(*net.TCPConn)
	}
	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *ShadowsocksNoneTCPClient) NativeInitialPayload() bool {
	return true
}

// ShadowsocksNoneTCPServer implements the zerocopy TCPServer interface.
type ShadowsocksNoneTCPServer struct{}

func NewShadowsocksNoneTCPServer() *ShadowsocksNoneTCPServer {
	return &ShadowsocksNoneTCPServer{}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *ShadowsocksNoneTCPServer) Accept(tc *net.TCPConn) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewShadowsocksNoneStreamServerReadWriter(tc)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *ShadowsocksNoneTCPServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *ShadowsocksNoneTCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.JustClose
}

// Socks5TCPClient implements the zerocopy TCPClient interface.
type Socks5TCPClient struct {
	address string
	dialer  tfo.Dialer
}

func NewSocks5TCPClient(address string, dialerTFO bool, dialerFwmark int) *Socks5TCPClient {
	return &Socks5TCPClient{
		address: address,
		dialer:  conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *Socks5TCPClient) Dial(targetAddr conn.Addr, payload []byte) (tc *net.TCPConn, rw zerocopy.ReadWriter, err error) {
	nc, err := c.dialer.Dial("tcp", c.address, nil)
	if err != nil {
		return
	}
	tc = nc.(*net.TCPConn)

	rw, err = NewSocks5StreamClientReadWriter(tc, targetAddr)
	if err != nil {
		tc.Close()
		return
	}

	if len(payload) > 0 {
		if _, err = rw.WriteZeroCopy(payload, 0, len(payload)); err != nil {
			tc.Close()
		}
	}
	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *Socks5TCPClient) NativeInitialPayload() bool {
	return false
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

// Accept implements the zerocopy.TCPServer Accept method.
func (s *Socks5TCPServer) Accept(tc *net.TCPConn) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(tc, s.enableTCP, s.enableUDP, tc)
	if err == socks5.ErrUDPAssociateDone {
		err = zerocopy.ErrAcceptDoneNoRelay
	}
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *Socks5TCPServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *Socks5TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.JustClose
}

package direct

import (
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go"
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
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (tfoConn tfo.Conn, rw zerocopy.ReadWriter, err error) {
	_, tfoConn, err = conn.DialTFOWithPayload(&c.dialer, targetAddr.String(), payload)
	if err != nil {
		return
	}
	rw = &DirectStreamReadWriter{rw: tfoConn}
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
	targetAddr socks5.Addr
}

func NewTCPServer(targetAddr socks5.Addr) *TCPServer {
	return &TCPServer{
		targetAddr: targetAddr,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	return &DirectStreamReadWriter{
		rw: conn,
	}, s.targetAddr, nil, nil
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *TCPServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return nil
}

// ShadowsocksNoneTCPClient implements the zerocopy TCPClient interface.
type ShadowsocksNoneTCPClient struct {
	address string
	dialer  tfo.Dialer
}

func NewShadowsocksNoneTCPClient(address string, dialerTFO bool, dialerFwmark int) *ShadowsocksNoneTCPClient {
	return &ShadowsocksNoneTCPClient{
		address: address,
		dialer:  conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ShadowsocksNoneTCPClient) Dial(targetAddr socks5.Addr, payload []byte) (tfoConn tfo.Conn, rw zerocopy.ReadWriter, err error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return
	}
	tfoConn = netConn.(tfo.Conn)
	rw, err = NewShadowsocksNoneStreamClientReadWriter(tfoConn, targetAddr, payload)
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
func (s *ShadowsocksNoneTCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewShadowsocksNoneStreamServerReadWriter(conn)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *ShadowsocksNoneTCPServer) NativeInitialPayload() bool {
	return false
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *ShadowsocksNoneTCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return nil
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
func (c *Socks5TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (tfoConn tfo.Conn, rw zerocopy.ReadWriter, err error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return
	}
	tfoConn = netConn.(tfo.Conn)

	rw, err = NewSocks5StreamClientReadWriter(tfoConn, targetAddr)
	if err != nil {
		return
	}

	if len(payload) > 0 {
		_, err = rw.WriteZeroCopy(payload, 0, len(payload))
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
func (s *Socks5TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(conn, s.enableTCP, s.enableUDP, conn)
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
	return nil
}

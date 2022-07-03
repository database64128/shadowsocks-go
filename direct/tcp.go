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
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (zerocopy.Conn, error) {
	_, conn, err := conn.DialTFOWithPayload(&c.dialer, targetAddr.String(), payload)
	if err != nil {
		return nil, err
	}

	return zerocopy.NewTFOConn(&DirectStreamReadWriter{rw: conn}, conn), nil
}

// TCPServer is the client-side tunnel server.
//
// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	targetAddr socks5.Addr
}

func NewTCPServer(targetAddress string) (*TCPServer, error) {
	targetAddr, err := socks5.ParseAddr(targetAddress)
	if err != nil {
		return nil, err
	}

	return &TCPServer{
		targetAddr: targetAddr,
	}, nil
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
func (c *ShadowsocksNoneTCPClient) Dial(targetAddr socks5.Addr, payload []byte) (zerocopy.Conn, error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return nil, err
	}
	tfoConn := netConn.(tfo.Conn)

	rw, err := NewShadowsocksNoneStreamClientReadWriter(tfoConn, targetAddr)
	if err != nil {
		return nil, err
	}

	return zerocopy.NewTFOConn(rw, tfoConn), nil
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
func (c *Socks5TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (zerocopy.Conn, error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return nil, err
	}
	tfoConn := netConn.(tfo.Conn)

	rw, err := NewSocks5StreamClientReadWriter(tfoConn, targetAddr)
	if err != nil {
		return nil, err
	}

	return zerocopy.NewTFOConn(rw, tfoConn), nil
}

// Socks5TCPServer implements the zerocopy TCPServer interface.
type Socks5TCPServer struct {
	enableTCP    bool
	enableUDP    bool
	udpBoundAddr socks5.Addr
}

func NewSocks5TCPServer(enableTCP, enableUDP bool, udpBoundAddr socks5.Addr) *Socks5TCPServer {
	return &Socks5TCPServer{
		enableTCP:    enableTCP,
		enableUDP:    enableUDP,
		udpBoundAddr: udpBoundAddr,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *Socks5TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(conn, s.enableTCP, s.enableUDP, s.udpBoundAddr)
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *Socks5TCPServer) NativeInitialPayload() bool {
	return false
}

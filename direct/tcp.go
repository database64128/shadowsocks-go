package direct

import (
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	name   string
	dialer tfo.Dialer
}

func NewTCPClient(name string, dialerTFO bool, dialerFwmark int) *TCPClient {
	return &TCPClient{
		name:   name,
		dialer: conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// String implements the zerocopy.TCPClient String method.
func (c *TCPClient) String() string {
	return c.name
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	nc, err := c.dialer.Dial("tcp", targetAddr.String(), payload)
	if err != nil {
		return
	}
	rawRW = nc.(zerocopy.DirectReadWriteCloser)
	rw = &DirectStreamReadWriter{rw: rawRW}
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
func (s *TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	return &DirectStreamReadWriter{rw: rawRW}, s.targetAddr, nil, "", nil
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
	name string
	tco  *zerocopy.TCPConnOpener
}

func NewShadowsocksNoneTCPClient(name, address string, dialerTFO bool, dialerFwmark int) *ShadowsocksNoneTCPClient {
	return &ShadowsocksNoneTCPClient{
		name: name,
		tco:  zerocopy.NewTCPConnOpener(conn.NewDialer(dialerTFO, dialerFwmark), "tcp", address),
	}
}

// String implements the zerocopy.TCPClient String method.
func (c *ShadowsocksNoneTCPClient) String() string {
	return c.name
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *ShadowsocksNoneTCPClient) Dial(targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	rw, rawRW, err = NewShadowsocksNoneStreamClientReadWriter(c.tco, targetAddr, payload)
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
func (s *ShadowsocksNoneTCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewShadowsocksNoneStreamServerReadWriter(rawRW)
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
	name    string
	address string
	dialer  tfo.Dialer
}

func NewSocks5TCPClient(name, address string, dialerTFO bool, dialerFwmark int) *Socks5TCPClient {
	return &Socks5TCPClient{
		name:    name,
		address: address,
		dialer:  conn.NewDialer(dialerTFO, dialerFwmark),
	}
}

// String implements the zerocopy.TCPClient String method.
func (c *Socks5TCPClient) String() string {
	return c.name
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *Socks5TCPClient) Dial(targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	nc, err := c.dialer.Dial("tcp", c.address, nil)
	if err != nil {
		return
	}
	rawRW = nc.(zerocopy.DirectReadWriteCloser)

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
func (s *Socks5TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	rw, targetAddr, err = NewSocks5StreamServerReadWriter(rawRW, s.enableTCP, s.enableUDP)
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

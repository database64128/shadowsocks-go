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
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (zerocopy.ReadWriter, error) {
	_, conn, err := conn.DialTFOWithPayload(&c.dialer, targetAddr.String(), payload)
	if err != nil {
		return nil, err
	}

	return &DirectStreamReadWriter{
		rw: conn,
	}, nil
}

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

func (s *TCPServer) NativeInitialPayload() bool {
	return false
}

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
func (c *TCPClient) Dial(targetAddr socks5.Addr) (zerocopy.ReadWriter, error) {
	conn, err := c.dialer.Dial("tcp", targetAddr.String())
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
func (s *TCPServer) Accept(conn tfo.Conn) (targetAddr socks5.Addr, rw zerocopy.ReadWriter, err error) {
	return s.targetAddr, &DirectStreamReadWriter{
		rw: conn,
	}, nil
}

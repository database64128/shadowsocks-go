package ss2022

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
	return nil, nil
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct{}

func NewTCPServer() *TCPServer {
	return nil
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(conn tfo.Conn) (targetAddr socks5.Addr, rw zerocopy.ReadWriter, err error) {
	return nil, nil, nil
}

package ss2022

import (
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	address      string
	dialer       tfo.Dialer
	cipherConfig *CipherConfig
}

func NewTCPClient(address string, dialerTFO bool, dialerFwmark int, cipherConfig *CipherConfig) *TCPClient {
	return &TCPClient{
		address:      address,
		dialer:       conn.NewDialer(dialerTFO, dialerFwmark),
		cipherConfig: cipherConfig,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (n int, rw zerocopy.ReadWriter, err error) {
	n, conn, err := conn.DialTFOWithPayload(&c.dialer, c.address, payload)
	if err != nil {
		return
	}

	rw, err = NewShadowStreamClientReadWriter(conn, c.cipherConfig, targetAddr, payload)
	return
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	cipherConfig *CipherConfig
	saltPool     *SaltPool[string]
}

func NewTCPServer(cipherConfig *CipherConfig) *TCPServer {
	return &TCPServer{
		cipherConfig: cipherConfig,
		saltPool:     NewSaltPool[string](ReplayWindowDuration),
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	return NewShadowStreamServerReadWriter(conn, s.cipherConfig, s.saltPool)
}

func (s *TCPServer) NativeInitialPayload() bool {
	return true
}

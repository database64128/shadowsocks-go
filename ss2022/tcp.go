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
	eihPSKHashes [][IdentityHeaderLength]byte
}

func NewTCPClient(address string, dialerTFO bool, dialerFwmark int, cipherConfig *CipherConfig) *TCPClient {
	return &TCPClient{
		address:      address,
		dialer:       conn.NewDialer(dialerTFO, dialerFwmark),
		cipherConfig: cipherConfig,
		eihPSKHashes: cipherConfig.ClientPSKHashes(),
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (rw zerocopy.ReadWriter, err error) {
	conn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return
	}

	rw, err = NewShadowStreamClientReadWriter(conn.(tfo.Conn), c.cipherConfig, c.eihPSKHashes, targetAddr, payload)
	return
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	cipherConfig *CipherConfig
	saltPool     *SaltPool[string]
	uPSKMap      map[[IdentityHeaderLength]byte][]byte
}

func NewTCPServer(cipherConfig *CipherConfig) *TCPServer {
	return &TCPServer{
		cipherConfig: cipherConfig,
		saltPool:     NewSaltPool[string](ReplayWindowDuration),
		uPSKMap:      cipherConfig.ServerPSKHashMap(),
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	return NewShadowStreamServerReadWriter(conn, s.cipherConfig, s.saltPool, s.uPSKMap)
}

func (s *TCPServer) NativeInitialPayload() bool {
	return true
}

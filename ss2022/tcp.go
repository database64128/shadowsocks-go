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

func NewTCPClient(address string, dialerTFO bool, dialerFwmark int, cipherConfig *CipherConfig, eihPSKHashes [][IdentityHeaderLength]byte) *TCPClient {
	return &TCPClient{
		address:      address,
		dialer:       conn.NewDialer(dialerTFO, dialerFwmark),
		cipherConfig: cipherConfig,
		eihPSKHashes: eihPSKHashes,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr socks5.Addr, payload []byte) (tfoConn tfo.Conn, rw zerocopy.ReadWriter, err error) {
	netConn, err := c.dialer.Dial("tcp", c.address)
	if err != nil {
		return
	}
	tfoConn = netConn.(tfo.Conn)
	rw, err = NewShadowStreamClientReadWriter(tfoConn, c.cipherConfig, c.eihPSKHashes, targetAddr, payload)
	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *TCPClient) NativeInitialPayload() bool {
	return true
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	cipherConfig *CipherConfig
	saltPool     *SaltPool[string]
	uPSKMap      map[[IdentityHeaderLength]byte]*CipherConfig
}

func NewTCPServer(cipherConfig *CipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*CipherConfig) *TCPServer {
	return &TCPServer{
		cipherConfig: cipherConfig,
		saltPool:     NewSaltPool[string](ReplayWindowDuration),
		uPSKMap:      uPSKMap,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(conn tfo.Conn) (rw zerocopy.ReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	return NewShadowStreamServerReadWriter(conn, s.cipherConfig, s.saltPool, s.uPSKMap)
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *TCPServer) NativeInitialPayload() bool {
	return true
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.ForceReset
}

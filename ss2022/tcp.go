package ss2022

import (
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	tco          *zerocopy.TCPConnOpener
	cipherConfig *CipherConfig
	eihPSKHashes [][IdentityHeaderLength]byte
}

func NewTCPClient(address string, dialerTFO bool, dialerFwmark int, cipherConfig *CipherConfig, eihPSKHashes [][IdentityHeaderLength]byte) *TCPClient {
	return &TCPClient{
		tco:          zerocopy.NewTCPConnOpener(conn.NewDialer(dialerTFO, dialerFwmark), "tcp", address),
		cipherConfig: cipherConfig,
		eihPSKHashes: eihPSKHashes,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr conn.Addr, payload []byte) (tc *net.TCPConn, rw zerocopy.ReadWriter, err error) {
	rw, rawRW, err := NewShadowStreamClientReadWriter(c.tco, c.cipherConfig, c.eihPSKHashes, targetAddr, payload)
	if err == nil {
		tc = rawRW.(*net.TCPConn)
	}
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
func (s *TCPServer) Accept(tc *net.TCPConn) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	return NewShadowStreamServerReadWriter(tc, s.cipherConfig, s.saltPool, s.uPSKMap)
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *TCPServer) NativeInitialPayload() bool {
	return true
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.ForceReset
}

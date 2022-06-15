package zerocopy

import (
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/tfo-go"
)

// TCPClient is a protocol's TCP client.
type TCPClient interface {
	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns a ReadWriter for read-write access.
	Dial(targetAddr socks5.Addr, payload []byte) (n int, rw ReadWriter, err error)
}

// TCPServer provides a protocol's TCP service.
type TCPServer interface {
	// Accept takes a newly-accepted TCP connection and wraps it into a
	// protocol stream server.
	Accept(conn tfo.Conn) (rw ReadWriter, targetAddr socks5.Addr, payload []byte, err error)

	// NativeInitialPayload reports whether the protocol natively supports
	// sending the initial payload within or along with the request header.
	NativeInitialPayload() bool
}

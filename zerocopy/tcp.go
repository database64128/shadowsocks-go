package zerocopy

import (
	"net"
	"time"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/tfo-go"
)

// Conn extends the ReadWriter interface with features from TCP connections.
type Conn interface {
	ReadWriter

	// LocalAddr returns the local network address, if known.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address, if known.
	RemoteAddr() net.Addr

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail instead of blocking. The deadline applies to all future
	// and pending I/O, not just the immediately following call to
	// Read or Write. After a deadline has been exceeded, the
	// connection can be refreshed by setting a deadline in the future.
	//
	// If the deadline is exceeded a call to Read or Write or to other
	// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
	// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
	// The error's Timeout method will return true, but note that there
	// are other possible errors for which the Timeout method will
	// return true even if the deadline has not been exceeded.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error

	// SetLinger sets the behavior of Close on a connection which still
	// has data waiting to be sent or to be acknowledged.
	//
	// If sec < 0 (the default), the operating system finishes sending the
	// data in the background.
	//
	// If sec == 0, the operating system discards any unsent or
	// unacknowledged data.
	//
	// If sec > 0, the data is sent in the background as with sec < 0. On
	// some operating systems after sec seconds have elapsed any remaining
	// unsent data may be discarded.
	SetLinger(sec int) error

	// SetNoDelay controls whether the operating system should delay
	// packet transmission in hopes of sending fewer packets (Nagle's
	// algorithm).  The default is true (no delay), meaning that data is
	// sent as soon as possible after a Write.
	SetNoDelay(noDelay bool) error

	// SetKeepAlive sets whether the operating system should send
	// keep-alive messages on the connection.
	SetKeepAlive(keepalive bool) error

	// SetKeepAlivePeriod sets period between keep-alives.
	SetKeepAlivePeriod(d time.Duration) error
}

// TFOConn implements the Conn interface by wrapping a ReadWriter and a tfo.Conn.
type TFOConn struct {
	ReadWriter
	conn tfo.Conn
}

func NewTFOConn(rw ReadWriter, conn tfo.Conn) *TFOConn {
	return &TFOConn{
		ReadWriter: rw,
		conn:       conn,
	}
}

// LocalAddr implements the Conn LocalAddr method.
func (c *TFOConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr implements the Conn RemoteAddr method.
func (c *TFOConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements the Conn SetDeadline method.
func (c *TFOConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *TFOConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *TFOConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// SetLinger implements the Conn SetLinger method.
func (c *TFOConn) SetLinger(sec int) error {
	return c.conn.SetLinger(sec)
}

// SetNoDelay implements the Conn SetNoDelay method.
func (c *TFOConn) SetNoDelay(noDelay bool) error {
	return c.conn.SetNoDelay(noDelay)
}

// SetKeepAlive implements the Conn SetKeepAlive method.
func (c *TFOConn) SetKeepAlive(keepalive bool) error {
	return c.conn.SetKeepAlive(keepalive)
}

// SetKeepAlivePeriod implements the Conn SetKeepAlivePeriod method.
func (c *TFOConn) SetKeepAlivePeriod(d time.Duration) error {
	return c.conn.SetKeepAlivePeriod(d)
}

// TCPClient is a protocol's TCP client.
type TCPClient interface {
	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns a ReadWriter for read-write access.
	Dial(targetAddr socks5.Addr, payload []byte) (conn Conn, err error)
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

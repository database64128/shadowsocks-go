package netio

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
)

// Reader is an alias for [io.Reader].
type Reader = io.Reader

// Writer is [io.Writer] with CloseWrite.
type Writer interface {
	io.Writer

	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// ReadWriter is [io.ReadWriter] with CloseWrite.
type ReadWriter interface {
	Reader
	Writer
}

// BidirectionalCopy copies data between two ReadWriters in both directions,
// until either EOF is reached or an error occurs, after which it closes the
// writing side of the receiving ReadWriter.
//
// It returns the number of bytes copied in each direction, and all errors
// encountered during the copy wrapped together.
func BidirectionalCopy(left, right ReadWriter) (nl2r, nr2l int64, err error) {
	var (
		wg     sync.WaitGroup
		l2rErr error
	)

	wg.Add(1)
	go func() {
		nl2r, l2rErr = io.Copy(right, left)
		_ = right.CloseWrite()
		wg.Done()
	}()

	nr2l, err = io.Copy(left, right)
	_ = left.CloseWrite()
	wg.Wait()

	return nl2r, nr2l, errors.Join(l2rErr, err)
}

// Conn is [net.Conn] with CloseWrite.
type Conn interface {
	net.Conn

	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// StreamClient creates dialers for stream connections.
type StreamClient interface {
	// NewStreamDialer returns a new stream dialer and its information.
	NewStreamDialer() (StreamDialer, StreamDialerInfo)
}

// StreamDialer establishes stream connections to servers.
type StreamDialer interface {
	// DialStream establishes a stream connection to the given network address.
	// The optional initial payload, if not empty, is sent in full to the remote
	// peer via the established connection before returning.
	DialStream(ctx context.Context, addr conn.Addr, payload []byte) (Conn, error)
}

// StreamDialerInfo contains information about a stream dialer.
type StreamDialerInfo struct {
	// Name is the name of the dialer.
	Name string

	// NativeInitialPayload indicates whether the dialer supports sending
	// the initial payload within or along with the connection request
	// without additional round trips.
	NativeInitialPayload bool
}

var ErrHandleStreamDone = errors.New("the stream connection has been handled")

// StreamServer handles incoming stream connections.
type StreamServer interface {
	// StreamServerInfo returns information about the stream server.
	StreamServerInfo() StreamServerInfo

	// HandleStream initiates processing of a new stream connection.
	//
	// If the stream connection is not a connection request, and the processing
	// is completed successfully, [ErrHandleStreamDone] is returned.
	//
	// If the processing fails, bytes read from the connection may be returned
	// as the payload in the connection request.
	HandleStream(c Conn, logger *zap.Logger) (ConnRequest, error)
}

// StreamServerInfo contains information about a stream server.
type StreamServerInfo struct {
	// NativeInitialPayload indicates whether the server supports receiving
	// the initial payload within or along with the connection request
	// without additional round trips.
	NativeInitialPayload bool
}

// ConnRequest consists of an accepted stream connection and its associated information.
type ConnRequest struct {
	// PendingConn is the accepted stream connection, pending further action.
	PendingConn

	// Addr is the destination address.
	Addr conn.Addr

	// Payload is the optional initial payload.
	Payload []byte

	// Username identifies the initiator of the connection.
	Username string
}

// PendingConn is an accepted stream connection, pending further action.
type PendingConn interface {
	// Proceed proceeds with the pending connection and returns the established connection.
	Proceed() (Conn, error)

	// Abort aborts the pending connection with the given dial result.
	Abort(dialResult conn.DialResult) error
}

// NopPendingConn wraps a [Conn] as a no-op [PendingConn].
func NopPendingConn(c Conn) PendingConn {
	return nopPendingConn{inner: c}
}

type nopPendingConn struct {
	inner Conn
}

func (c nopPendingConn) Proceed() (Conn, error) {
	return c.inner, nil
}

func (nopPendingConn) Abort(_ conn.DialResult) error {
	return nil
}

// StreamProxyServer proxies all incoming connections to a fixed destination address.
//
// StreamProxyServer implements [StreamServer].
type StreamProxyServer struct {
	addr conn.Addr
}

var _ StreamServer = (*StreamProxyServer)(nil)

// NewStreamProxyServer returns a [*StreamProxyServer] that proxies connections to addr.
func NewStreamProxyServer(addr conn.Addr) *StreamProxyServer {
	return &StreamProxyServer{addr: addr}
}

// StreamServerInfo implements [StreamServer.StreamServerInfo].
func (s *StreamProxyServer) StreamServerInfo() StreamServerInfo {
	return StreamServerInfo{
		NativeInitialPayload: false,
	}
}

// HandleStream implements [StreamServer.HandleStream].
func (s *StreamProxyServer) HandleStream(c Conn, _ *zap.Logger) (ConnRequest, error) {
	return ConnRequest{
		PendingConn: NopPendingConn(c),
		Addr:        s.addr,
	}, nil
}

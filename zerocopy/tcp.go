package zerocopy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/fastrand"
	"go.uber.org/zap"
)

var (
	ErrAcceptDoneNoRelay     = errors.New("the accepted connection has been handled without relaying")
	ErrAcceptRequiresTCPConn = errors.New("rawRW is required to be a *net.TCPConn")
)

// TCPClientInfo contains information about a TCP client.
type TCPClientInfo struct {
	// Name is the name of the TCP client.
	Name string

	// NativeInitialPayload reports whether the protocol natively supports
	// sending the initial payload within or along with the request header.
	NativeInitialPayload bool
}

// TCPClient is a protocol's TCP client.
type TCPClient interface {
	// ClientInfo returns information about the TCP client.
	Info() TCPClientInfo

	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns the established connection and a ReadWriter for read-write access.
	Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW DirectReadWriteCloser, rw ReadWriter, err error)
}

// TCPServerInfo contains information about a TCP server.
type TCPServerInfo struct {
	// NativeInitialPayload reports whether the protocol natively supports
	// sending the initial payload within or along with the request header.
	NativeInitialPayload bool

	// DefaultTCPConnCloser is the server's default function for handling a potentially malicious TCP connection.
	DefaultTCPConnCloser TCPConnCloser
}

// TCPServer provides a protocol's TCP service.
type TCPServer interface {
	// ServerInfo returns information about the TCP server.
	Info() TCPServerInfo

	// Accept takes a newly-accepted TCP connection and wraps it into a protocol stream server.
	//
	// To make it easier to write tests, rawRW is of type [DirectReadWriteCloser].
	// If the stream server needs to access TCP-specific features, it must type-assert and return
	// [ErrAcceptRequiresTCPConn] on error.
	//
	// If the returned error is [ErrAcceptDoneNoRelay], the connection has been handled by this method.
	// Two-way relay is not needed.
	//
	// If accept fails, the returned payload must be either nil/empty or the data that has been read
	// from the connection.
	Accept(rawRW DirectReadWriteCloser) (rw ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error)
}

// TCPConnOpener stores information for opening TCP connections.
//
// TCPConnOpener implements the DirectReadWriteCloserOpener interface.
type TCPConnOpener struct {
	dialer           conn.Dialer
	network, address string
}

// NewTCPConnOpener returns a new TCPConnOpener using the specified dialer, network and address.
func NewTCPConnOpener(dialer conn.Dialer, network, address string) *TCPConnOpener {
	return &TCPConnOpener{
		dialer:  dialer,
		network: network,
		address: address,
	}
}

// Open implements the DirectReadWriteCloserOpener Open method.
func (o *TCPConnOpener) Open(ctx context.Context, b []byte) (DirectReadWriteCloser, error) {
	return o.dialer.DialTCP(ctx, o.network, o.address, b)
}

// TCPConnCloser handles a potentially malicious TCP connection.
// Upon returning, the TCP connection is safe to close.
type TCPConnCloser func(conn *net.TCPConn, logger *zap.Logger)

// JustClose closes the TCP connection without any special handling.
func JustClose(conn *net.TCPConn, logger *zap.Logger) {
}

// ForceReset forces a reset of the TCP connection, regardless of
// whether there's unread data or not.
func ForceReset(conn *net.TCPConn, logger *zap.Logger) {
	if err := conn.SetLinger(0); err != nil {
		logger.Warn("Failed to set SO_LINGER on TCP connection", zap.Error(err))
	}
	logger.Info("Forcing RST on TCP connection")
}

// CloseWriteDrain closes the write end of the TCP connection,
// then drain the read end.
func CloseWriteDrain(conn *net.TCPConn, logger *zap.Logger) {
	if err := conn.CloseWrite(); err != nil {
		logger.Warn("Failed to close write half of TCP connection", zap.Error(err))
	}

	n, err := io.Copy(io.Discard, conn)
	logger.Info("Drained TCP connection",
		zap.Int64("bytesRead", n),
		zap.Error(err),
	)
}

// ReplyWithGibberish keeps reading and replying with random garbage until EOF or error.
func ReplyWithGibberish(conn *net.TCPConn, logger *zap.Logger) {
	const (
		riBits = 7
		riMask = 1<<riBits - 1
		riMax  = 64 / riBits
	)

	var (
		ri        uint64
		remaining int
	)

	const (
		bufBaseSize    = 1 << 14
		bufVarSizeMask = bufBaseSize - 1
	)

	var (
		bytesRead    int64
		bytesWritten int64
		n            int
		err          error
	)

	b := make([]byte, bufBaseSize+fastrand.Uint()&bufVarSizeMask) // [16k, 32k)

	for {
		n, err = conn.Read(b)
		bytesRead += int64(n)
		if err != nil { // For TCPConn, when err == io.EOF, n == 0.
			break
		}

		// n is in [129, 256].
		// getrandom(2) won't block if the request size is not greater than 256.
		if remaining == 0 {
			ri = fastrand.Uint64()
			remaining = riMax
		}
		n = 129 + int(ri&riMask)
		ri >>= riBits
		remaining--

		garbage := b[:n]
		_, err = rand.Read(garbage)
		if err != nil {
			panic(err)
		}

		n, err = conn.Write(garbage)
		bytesWritten += int64(n)
		if err != nil {
			break
		}
	}

	logger.Info("Replied with gibberish",
		zap.Int64("bytesRead", bytesRead),
		zap.Int64("bytesWritten", bytesWritten),
		zap.Error(err),
	)
}

// ParseRejectPolicy parses a string representation of a reject policy.
func ParseRejectPolicy(rejectPolicy string, serverDefault TCPConnCloser) (TCPConnCloser, error) {
	switch rejectPolicy {
	case "":
		return serverDefault, nil
	case "JustClose":
		return JustClose, nil
	case "ForceReset":
		return ForceReset, nil
	case "CloseWriteDrain":
		return CloseWriteDrain, nil
	case "ReplyWithGibberish":
		return ReplyWithGibberish, nil
	default:
		return nil, fmt.Errorf("invalid reject policy: %s", rejectPolicy)
	}
}

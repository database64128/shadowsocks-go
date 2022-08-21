package zerocopy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
)

var ErrAcceptDoneNoRelay = errors.New("the accepted connection has been handled without relaying")

// InitialPayloader is implemented by a protocol's TCP client or server
// when the protocol's initial handshake message can carry payload.
type InitialPayloader interface {
	// NativeInitialPayload reports whether the protocol natively supports
	// sending the initial payload within or along with the request header.
	//
	// No matter true or false, the Dial method must process the initial payload.
	//
	// When false, the Accept method will not return non-empty initial payload.
	NativeInitialPayload() bool
}

// TCPClient is a protocol's TCP client.
type TCPClient interface {
	InitialPayloader

	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns the established connection and a ReadWriter for read-write access.
	Dial(targetAddr conn.Addr, payload []byte) (tfoConn tfo.Conn, rw ReadWriter, err error)
}

// TCPServer provides a protocol's TCP service.
type TCPServer interface {
	InitialPayloader

	// Accept takes a newly-accepted TCP connection and wraps it into a
	// protocol stream server.
	//
	// If the returned error is ErrAcceptDoneNoRelay, the connection has been handled by this method.
	// Two-way relay is not needed.
	Accept(conn tfo.Conn) (rw ReadWriter, targetAddr conn.Addr, payload []byte, err error)

	// DefaultTCPConnCloser returns the default function to handle the closing
	// of a potentially malicious TCP connection.
	//
	// If no special handling is required, return nil.
	DefaultTCPConnCloser() TCPConnCloser
}

// TCPConnCloser handles a potentially malicious TCP connection.
// Upon returning, the TCP connection is safe to close.
type TCPConnCloser func(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger)

// Do invokes the TCPConnCloser if it's not nil.
func (c TCPConnCloser) Do(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger) {
	if c != nil {
		c(conn, serverName, listenAddress, clientAddress, logger)
	}
}

// ForceReset forces a reset of the TCP connection, regardless of
// whether there's unread data or not.
func ForceReset(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger) {
	if err := conn.SetLinger(0); err != nil {
		logger.Warn("Failed to set SO_LINGER on TCP connection",
			zap.String("server", serverName),
			zap.String("listenAddress", listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)
	}

	logger.Info("Forcing RST on TCP connection",
		zap.String("server", serverName),
		zap.String("listenAddress", listenAddress),
		zap.String("clientAddress", clientAddress),
	)
}

// CloseWriteDrain closes the write end of the TCP connection,
// then drain the read end.
func CloseWriteDrain(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger) {
	if err := conn.CloseWrite(); err != nil {
		logger.Warn("Failed to close write half of TCP connection",
			zap.String("server", serverName),
			zap.String("listenAddress", listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)
	}

	n, err := io.Copy(io.Discard, conn)
	logger.Info("Drained TCP connection",
		zap.String("server", serverName),
		zap.String("listenAddress", listenAddress),
		zap.String("clientAddress", clientAddress),
		zap.Int64("bytesRead", n),
		zap.Error(err),
	)
}

// ReplyWithGibberish keeps reading and replying with random garbage until EOF or error.
func ReplyWithGibberish(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger) {
	var (
		bytesRead, bytesWritten int64
		n                       int
		err                     error
	)

	b := make([]byte, 65535) // Hopefully b is stack allocated.

	for {
		n, err = conn.Read(b)
		bytesRead += int64(n)
		if err != nil { // For TCPConn, when err == io.EOF, n == 0.
			break
		}

		// n is in [128, 256].
		// getrandom(2) won't block if the request size is not greater than 256.
		n = 128 + mrand.Intn(129)
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
		zap.String("server", serverName),
		zap.String("listenAddress", listenAddress),
		zap.String("clientAddress", clientAddress),
		zap.Int64("bytesRead", bytesRead),
		zap.Int64("bytesWritten", bytesWritten),
		zap.Error(err),
	)
}

// ParseRejectPolicy parses a string representation of a reject policy.
func ParseRejectPolicy(rejectPolicy string, server TCPServer) (TCPConnCloser, error) {
	switch rejectPolicy {
	case "":
		return server.DefaultTCPConnCloser(), nil
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

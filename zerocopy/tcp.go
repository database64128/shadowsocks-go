package zerocopy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/tfo-go/v2"
	"go.uber.org/zap"
)

var (
	ErrAcceptDoneNoRelay     = errors.New("the accepted connection has been handled without relaying")
	ErrAcceptRequiresTCPConn = errors.New("rawRW is required to be a *net.TCPConn")
)

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
	fmt.Stringer
	InitialPayloader

	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns the established connection and a ReadWriter for read-write access.
	Dial(targetAddr conn.Addr, payload []byte) (rawRW DirectReadWriteCloser, rw ReadWriter, err error)
}

// TCPServer provides a protocol's TCP service.
type TCPServer interface {
	InitialPayloader

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

	// DefaultTCPConnCloser returns the default function to handle the closing
	// of a potentially malicious TCP connection.
	//
	// If no special handling is required, return nil.
	DefaultTCPConnCloser() TCPConnCloser
}

// TCPConnOpener stores information for opening TCP connections.
//
// TCPConnOpener implements the DirectReadWriteCloserOpener interface.
type TCPConnOpener struct {
	dialer           tfo.Dialer
	network, address string
}

// NewTCPConnOpener returns a new TCPConnOpener using the specified dialer, network and address.
func NewTCPConnOpener(dialer tfo.Dialer, network, address string) *TCPConnOpener {
	return &TCPConnOpener{
		dialer:  dialer,
		network: network,
		address: address,
	}
}

// Open implements the DirectReadWriteCloserOpener Open method.
func (o *TCPConnOpener) Open(b []byte) (DirectReadWriteCloser, error) {
	c, err := o.dialer.Dial(o.network, o.address, b)
	if err != nil {
		return nil, err
	}
	return c.(DirectReadWriteCloser), nil
}

// TCPConnCloser handles a potentially malicious TCP connection.
// Upon returning, the TCP connection is safe to close.
type TCPConnCloser func(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger)

// JustClose closes the TCP connection without any special handling.
func JustClose(conn *net.TCPConn, serverName, listenAddress, clientAddress string, logger *zap.Logger) {
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
	const (
		riBits = 7
		riMask = 1<<riBits - 1
		riMax  = 63 / riBits
	)

	var (
		ri        int64
		remaining int
	)

	rng := mrand.NewSource(time.Now().UnixNano())

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

	b := make([]byte, bufBaseSize+int(rng.Int63()&bufVarSizeMask)) // [16k, 32k)

	for {
		n, err = conn.Read(b)
		bytesRead += int64(n)
		if err != nil { // For TCPConn, when err == io.EOF, n == 0.
			break
		}

		// n is in [129, 256].
		// getrandom(2) won't block if the request size is not greater than 256.
		if remaining == 0 {
			ri = rng.Int63()
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

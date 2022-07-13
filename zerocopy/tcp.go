package zerocopy

import (
	"fmt"
	"io"
	"net"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
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
	InitialPayloader

	// Dial creates a connection to the target address under the protocol's
	// encapsulation and returns the established connection and a ReadWriter for read-write access.
	Dial(targetAddr socks5.Addr, payload []byte) (tfoConn tfo.Conn, rw ReadWriter, err error)
}

// TCPServer provides a protocol's TCP service.
type TCPServer interface {
	InitialPayloader

	// Accept takes a newly-accepted TCP connection and wraps it into a
	// protocol stream server.
	Accept(conn tfo.Conn) (rw ReadWriter, targetAddr socks5.Addr, payload []byte, err error)

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

// ParseRejectPolicy parses a string representation of a reject policy.
func ParseRejectPolicy(rejectPolicy string, server TCPServer) (TCPConnCloser, error) {
	switch rejectPolicy {
	case "":
		return server.DefaultTCPConnCloser(), nil
	case "ForceReset":
		return ForceReset, nil
	case "CloseWriteDrain":
		return CloseWriteDrain, nil
	default:
		return nil, fmt.Errorf("invalid reject policy: %s", rejectPolicy)
	}
}

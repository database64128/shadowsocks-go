package ss2022

import (
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"

	"github.com/database64128/shadowsocks-go/conn"
	"go.uber.org/zap"
)

// PaddingPolicy is a function that takes the target address and
// returns whether padding should be added.
type PaddingPolicy func(targetAddr conn.Addr) (shouldPad bool)

// NoPadding is a PaddingPolicy that never adds padding.
func NoPadding(_ conn.Addr) bool {
	return false
}

// PadAll is a PaddingPolicy that adds padding to all traffic.
func PadAll(_ conn.Addr) bool {
	return true
}

// PadPlainDNS is a PaddingPolicy that adds padding to plain DNS traffic.
func PadPlainDNS(targetAddr conn.Addr) bool {
	return targetAddr.Port() == 53
}

// ParsePaddingPolicy returns the padding policy represented by s.
func ParsePaddingPolicy(s string) (PaddingPolicy, error) {
	switch s {
	case "NoPadding":
		return NoPadding, nil
	case "PadAll":
		return PadAll, nil
	case "PadPlainDNS", "":
		return PadPlainDNS, nil
	default:
		return nil, fmt.Errorf("invalid padding policy: %q", s)
	}
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (p *PaddingPolicy) UnmarshalText(text []byte) error {
	switch string(text) {
	case "NoPadding":
		*p = NoPadding
	case "PadAll":
		*p = PadAll
	case "PadPlainDNS", "":
		*p = PadPlainDNS
	default:
		return fmt.Errorf("invalid padding policy: %q", text)
	}
	return nil
}

// Initialize sets the default padding policy if p is nil.
func (p *PaddingPolicy) Initialize() {
	if *p == nil {
		*p = PadPlainDNS
	}
}

// RejectPolicy is a function that handles a potentially malicious TCP connection.
// Upon returning, it's safe to close the connection.
type RejectPolicy func(c *net.TCPConn, logger *zap.Logger)

// JustClose closes the TCP connection without any special handling.
func JustClose(_ *net.TCPConn, _ *zap.Logger) {
}

// ForceReset forces a reset of the TCP connection, regardless of whether there's unread data or not.
func ForceReset(c *net.TCPConn, logger *zap.Logger) {
	if err := c.SetLinger(0); err != nil {
		logger.Warn("Failed to set SO_LINGER on TCP connection", zap.Error(err))
	}
	logger.Info("Forcing RST on TCP connection")
}

// CloseWriteDrain closes the write end of the TCP connection, then drain the read end.
func CloseWriteDrain(c *net.TCPConn, logger *zap.Logger) {
	if err := c.CloseWrite(); err != nil {
		logger.Warn("Failed to close write half of TCP connection", zap.Error(err))
	}

	n, err := io.Copy(io.Discard, c)
	logger.Info("Drained TCP connection",
		zap.Int64("bytesRead", n),
		zap.Error(err),
	)
}

// ReplyWithGibberish keeps reading and replying with random garbage until EOF or error.
func ReplyWithGibberish(c *net.TCPConn, logger *zap.Logger) {
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
		bufMaxSize     = bufBaseSize + bufVarSizeMask
	)

	var (
		bytesRead    int64
		bytesWritten int64
		n            int
		err          error
	)

	b := make([]byte, bufMaxSize)
	b = b[:bufBaseSize+mrand.Uint64()&bufVarSizeMask] // [16k, 32k)

	for {
		n, err = c.Read(b)
		bytesRead += int64(n)
		if err != nil { // For TCPConn, when err == io.EOF, n == 0.
			break
		}

		// n is in [129, 256].
		// getrandom(2) won't block if the request size is not greater than 256.
		if remaining == 0 {
			ri = mrand.Uint64()
			remaining = riMax
		}
		n = 129 + int(ri&riMask)
		ri >>= riBits
		remaining--

		garbage := b[:n]
		rand.Read(garbage)

		n, err = c.Write(garbage)
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

// ParseRejectPolicy returns the reject policy represented by s.
func ParseRejectPolicy(s string) (RejectPolicy, error) {
	switch s {
	case "JustClose":
		return JustClose, nil
	case "ForceReset", "":
		return ForceReset, nil
	case "CloseWriteDrain":
		return CloseWriteDrain, nil
	case "ReplyWithGibberish":
		return ReplyWithGibberish, nil
	default:
		return nil, fmt.Errorf("invalid reject policy: %q", s)
	}
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (p *RejectPolicy) UnmarshalText(text []byte) error {
	switch string(text) {
	case "JustClose":
		*p = JustClose
	case "ForceReset", "":
		*p = ForceReset
	case "CloseWriteDrain":
		*p = CloseWriteDrain
	case "ReplyWithGibberish":
		*p = ReplyWithGibberish
	default:
		return fmt.Errorf("invalid reject policy: %q", text)
	}
	return nil
}

// Initialize sets the default reject policy if p is nil.
func (p *RejectPolicy) Initialize() {
	if *p == nil {
		*p = ForceReset
	}
}

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

// Unify the *PolicyField structs once Go has better generics support.

// PaddingPolicyField provides textual representation for a padding policy function.
//
// PaddingPolicyField implements [encoding.TextAppender], [encoding.TextMarshaler], and [encoding.TextUnmarshaler].
type PaddingPolicyField struct {
	policy PaddingPolicy
	name   string
}

// NewPaddingPolicyField returns a [PaddingPolicyField] for the given padding policy name.
func NewPaddingPolicyField(name string) (PaddingPolicyField, error) {
	policy, err := ParsePaddingPolicy(name)
	if err != nil {
		return PaddingPolicyField{}, err
	}
	return PaddingPolicyField{
		policy: policy,
		name:   name,
	}, nil
}

// Policy returns the padding policy function.
func (p PaddingPolicyField) Policy() PaddingPolicy {
	if p.policy == nil {
		return PadPlainDNS
	}
	return p.policy
}

// Name returns the name of the padding policy.
func (p PaddingPolicyField) Name() string {
	if p.name == "" {
		return "PadPlainDNS"
	}
	return p.name
}

// AppendText implements [encoding.TextAppender].
func (p PaddingPolicyField) AppendText(b []byte) ([]byte, error) {
	return append(b, p.name...), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (p PaddingPolicyField) MarshalText() ([]byte, error) {
	return []byte(p.name), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (p *PaddingPolicyField) UnmarshalText(text []byte) error {
	if err := p.policy.UnmarshalText(text); err != nil {
		return err
	}
	p.name = string(text)
	return nil
}

// RejectPolicyField provides textual representation for a reject policy function.
//
// RejectPolicyField implements [encoding.TextAppender], [encoding.TextMarshaler], and [encoding.TextUnmarshaler].
type RejectPolicyField struct {
	policy RejectPolicy
	name   string
}

// NewRejectPolicyField returns a [RejectPolicyField] for the given reject policy name.
func NewRejectPolicyField(name string) (RejectPolicyField, error) {
	policy, err := ParseRejectPolicy(name)
	if err != nil {
		return RejectPolicyField{}, err
	}
	return RejectPolicyField{
		policy: policy,
		name:   name,
	}, nil
}

// Policy returns the reject policy function.
func (p RejectPolicyField) Policy() RejectPolicy {
	if p.policy == nil {
		return JustClose
	}
	return p.policy
}

// Name returns the name of the reject policy.
func (p RejectPolicyField) Name() string {
	if p.name == "" {
		return "JustClose"
	}
	return p.name
}

// AppendText implements [encoding.TextAppender].
func (p RejectPolicyField) AppendText(b []byte) ([]byte, error) {
	return append(b, p.name...), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (p RejectPolicyField) MarshalText() ([]byte, error) {
	return []byte(p.name), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (p *RejectPolicyField) UnmarshalText(text []byte) error {
	if err := p.policy.UnmarshalText(text); err != nil {
		return err
	}
	p.name = string(text)
	return nil
}

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

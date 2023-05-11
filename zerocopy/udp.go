package zerocopy

import (
	"context"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

// UDPClientInfo contains information about a UDP client.
type UDPClientInfo struct {
	// Name is the name of the UDP client.
	Name string

	// PackerHeadroom is the headroom required by the packet packer.
	PackerHeadroom Headroom

	// MTU is the MTU of the client's designated network path.
	MTU int

	// ListenConfig is the [conn.ListenConfig] for opening client sockets.
	ListenConfig conn.ListenConfig
}

// UDPClientSession contains information about a UDP client session.
type UDPClientSession struct {
	// MaxPacketSize is the maximum size of outgoing packets.
	MaxPacketSize int

	// Packer is the packet packer for the session.
	Packer ClientPacker

	// Unpacker is the packet unpacker for the session.
	Unpacker ClientUnpacker

	// Close closes the session.
	Close func() error
}

// NoopClose is a no-op close function.
func NoopClose() error {
	return nil
}

// UDPClient stores information for creating new client sessions.
type UDPClient interface {
	// Info returns information about the client.
	Info() UDPClientInfo

	// NewSession creates a new client session, and returns the session info or an error.
	// The returned [UDPClientInfo] is always valid, even when session creation fails.
	NewSession(ctx context.Context) (UDPClientInfo, UDPClientSession, error)
}

// UDPNATServerInfo contains information about a UDP NAT server.
type UDPNATServerInfo struct {
	// UnpackerHeadroom is the headroom required by the packet unpacker.
	UnpackerHeadroom Headroom
}

// UDPNATServer stores information for creating new server sessions.
type UDPNATServer interface {
	// Info returns information about the server.
	Info() UDPNATServerInfo

	// NewUnpacker creates a new packet unpacker for the session.
	//
	// The returned unpacker is then used by the caller to unpack the incoming packet.
	// Upon successful unpacking, the unpacker's NewPacker method can be called to create
	// a corresponding packet packer.
	NewUnpacker() (ServerUnpacker, error)
}

// UDPSessionServerInfo contains information about a UDP session server.
type UDPSessionServerInfo struct {
	// UnpackerHeadroom is the headroom required by the packet unpacker.
	UnpackerHeadroom Headroom

	// MinNATTimeout is the server's minimum allowed NAT timeout.
	// 0 means no requirement.
	MinNATTimeout time.Duration
}

// UDPSessionServer deals with incoming sessions.
type UDPSessionServer interface {
	sync.Locker

	// Info returns information about the server.
	Info() UDPSessionServerInfo

	// SessionInfo extracts session ID from a received packet b.
	//
	// The returned session ID is then used by the caller to look up the session table.
	// If no matching entries were found, NewUnpacker should be called to create a new
	// packet unpacker for the packet.
	SessionInfo(b []byte) (csid uint64, err error)

	// NewUnpacker creates a new packet unpacker for the specified client session.
	//
	// The returned unpacker is then used by the caller to unpack the incoming packet.
	// Upon successful unpacking, the unpacker's NewPacker method can be called to create
	// a corresponding server session.
	NewUnpacker(b []byte, csid uint64) (serverUnpacker ServerUnpacker, username string, err error)
}

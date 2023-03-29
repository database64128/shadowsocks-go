package zerocopy

import (
	"sync"

	"github.com/database64128/shadowsocks-go/conn"
)

// UDPClientInfo contains information about a UDP client.
type UDPClientInfo struct {
	// Name is the name of the UDP client.
	Name string

	// PackerHeadroom is the headroom required by the packet packer.
	PackerHeadroom Headroom

	// MaxPacketSize is the maximum size of outgoing packets.
	MaxPacketSize int

	// ListenConfig is the [conn.ListenConfig] for opening client sockets.
	ListenConfig conn.ListenConfig
}

// UDPClient stores information for creating new client sessions.
type UDPClient interface {
	// Info returns information about the client.
	Info() UDPClientInfo

	// NewSession creates a new session and returns the client info,
	// the packet packer and unpacker for the session, or an error.
	NewSession() (UDPClientInfo, ClientPacker, ClientUnpacker, error)
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

	// NewSession creates a new session and returns the packet packer
	// and unpacker for the session, or an error.
	NewSession() (ServerPacker, ServerUnpacker, error)
}

// UDPSessionServerInfo contains information about a UDP session server.
type UDPSessionServerInfo struct {
	// UnpackerHeadroom is the headroom required by the packet unpacker.
	UnpackerHeadroom Headroom
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
	NewUnpacker(b []byte, csid uint64) (sessionServerUnpacker SessionServerUnpacker, username string, err error)
}

// SimpleUDPClient wraps a PackUnpacker and uses it for all sessions.
//
// SimpleUDPClient implements the UDPClient interface.
type SimpleUDPClient struct {
	info     UDPClientInfo
	packer   ClientPacker
	unpacker ClientUnpacker
}

// NewSimpleUDPClient wraps a PackUnpacker into a UDPClient and uses it for all sessions.
func NewSimpleUDPClient(name string, maxPacketSize int, listenConfig conn.ListenConfig, packer ClientPacker, unpacker ClientUnpacker) *SimpleUDPClient {
	return &SimpleUDPClient{
		info: UDPClientInfo{
			Name:           name,
			PackerHeadroom: packer.ClientPackerInfo().Headroom,
			MaxPacketSize:  maxPacketSize,
			ListenConfig:   listenConfig,
		},
		packer:   packer,
		unpacker: unpacker,
	}
}

// Info implements the UDPClient Info method.
func (c *SimpleUDPClient) Info() UDPClientInfo {
	return c.info
}

// NewSession implements the UDPClient NewSession method.
func (c *SimpleUDPClient) NewSession() (UDPClientInfo, ClientPacker, ClientUnpacker, error) {
	return c.info, c.packer, c.unpacker, nil
}

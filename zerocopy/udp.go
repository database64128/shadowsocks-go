package zerocopy

import (
	"fmt"
	"sync"
)

// UDPClient stores information for creating new client sessions.
type UDPClient interface {
	fmt.Stringer

	// Headroom reports client packer headroom requirements.
	Headroom

	// LinkInfo returns the maximum size of outgoing packets and fwmark.
	LinkInfo() (maxPacketSize, fwmark int)

	// NewSession creates a new session and returns the packet packer
	// and unpacker for the session, or an error.
	NewSession() (ClientPacker, ClientUnpacker, error)
}

// UDPNATServer stores information for creating new server sessions.
type UDPNATServer interface {
	// Headroom reports server unpacker headroom requirements.
	Headroom

	// NewSession creates a new session and returns the packet packer
	// and unpacker for the session, or an error.
	NewSession() (ServerPacker, ServerUnpacker, error)
}

// UDPSessionServer deals with incoming sessions.
type UDPSessionServer interface {
	sync.Locker

	// Headroom reports server unpacker headroom requirements.
	Headroom

	// SessionInfo extracts session ID from a received packet b.
	//
	// The returned session ID is then used by the caller to look up the session table.
	// If no matching entries were found, NewUnpacker should be called to create a new
	// packet unpacker for the packet.
	SessionInfo(b []byte) (csid uint64, err error)

	// NewUnpacker creates a new packet unpacker for the specified client session.
	//
	// The returned unpacker is then used by the caller to unpack the incoming packet.
	// Upon successful unpacking, NewPacker should be called to create a corresponding
	// server session.
	NewUnpacker(b []byte, csid uint64) (ServerUnpacker, error)

	// NewPacker creates a new server session for the specified client session
	// and returns the server session's packer, or an error.
	NewPacker(csid uint64) (ServerPacker, error)
}

// SimpleUDPClient wraps a PackUnpacker and uses it for all sessions.
//
// SimpleUDPClient implements the UDPClient interface.
type SimpleUDPClient struct {
	Headroom
	packer        ClientPacker
	unpacker      ClientUnpacker
	name          string
	maxPacketSize int
	fwmark        int
}

// NewSimpleUDPClient wraps a PackUnpacker into a UDPClient and uses it for all sessions.
func NewSimpleUDPClient(h Headroom, packer ClientPacker, unpacker ClientUnpacker, name string, maxPacketSize, fwmark int) *SimpleUDPClient {
	return &SimpleUDPClient{h, packer, unpacker, name, maxPacketSize, fwmark}
}

// String implements the UDPClient String method.
func (c *SimpleUDPClient) String() string {
	return c.name
}

// LinkInfo implements the UDPClient LinkInfo method.
func (c *SimpleUDPClient) LinkInfo() (int, int) {
	return c.maxPacketSize, c.fwmark
}

// NewSession implements the UDPClient NewSession method.
func (c *SimpleUDPClient) NewSession() (ClientPacker, ClientUnpacker, error) {
	return c.packer, c.unpacker, nil
}

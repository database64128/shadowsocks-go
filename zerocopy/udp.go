package zerocopy

import "net/netip"

// UDPClient stores the necessary information for creating new sessions.
type UDPClient interface {
	// Headroom reports client packer headroom requirements.
	Headroom

	// NewSession creates a new session and returns the packet packer
	// and unpacker for the session, or an error.
	NewSession() (Packer, Unpacker, error)

	// AddrPort returns the fixed target address and port of packed outgoing packets,
	// or false if individual packet's target address should be used.
	AddrPort() (addrPort netip.AddrPort, mtu, fwmark int, ok bool)
}

// UDPServer deals with incoming sessions.
type UDPServer interface {
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
	NewUnpacker(b []byte, csid uint64) (Unpacker, error)

	// NewPacker creates a new server session for the specified client session
	// and returns the server session's packer, or an error.
	NewPacker(csid uint64) (Packer, error)
}

// SimpleUDPClient wraps a PackUnpacker and uses it for all sessions.
//
// SimpleUDPClient implements the UDPClient interface.
type SimpleUDPClient struct {
	p             PackUnpacker
	addrPort      netip.AddrPort
	hasAddrPort   bool
	mtu           int
	fwmark        int
	frontHeadroom int
	rearHeadroom  int
}

// NewSimpleUDPClient wraps a PackUnpacker into a UDPClient and uses it for all sessions.
func NewSimpleUDPClient(p PackUnpacker, addrPort netip.AddrPort, hasAddrPort bool, mtu, fwmark, frontHeadroom, rearHeadroom int) *SimpleUDPClient {
	return &SimpleUDPClient{p, addrPort, hasAddrPort, mtu, fwmark, frontHeadroom, rearHeadroom}
}

// NewSession implements the UDPClient NewSession method.
func (c *SimpleUDPClient) NewSession() (Packer, Unpacker, error) {
	return c.p, c.p, nil
}

// AddrPort implements the UDPClient AddrPort method.
func (c *SimpleUDPClient) AddrPort() (netip.AddrPort, int, int, bool) {
	return c.addrPort, c.mtu, c.fwmark, c.hasAddrPort
}

// FrontHeadroom implements the UDPClient FrontHeadroom method.
func (c *SimpleUDPClient) FrontHeadroom() int {
	return c.frontHeadroom
}

// RearHeadroom implements the UDPClient RearHeadroom method.
func (c *SimpleUDPClient) RearHeadroom() int {
	return c.rearHeadroom
}

package zerocopy

// UDPClient stores the necessary information for creating new sessions.
type UDPClient interface {
	// NewSession creates a new session and returns the packet packer
	// and unpacker for the session, or an error.
	NewSession() (Packer, Unpacker, error)
}

// UDPServer deals with incoming sessions.
type UDPServer interface {
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

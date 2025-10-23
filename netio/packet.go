package netio

import (
	"context"
	"net/netip"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

// PacketClient establishes packet sessions to servers.
type PacketClient interface {
	// NewSession opens a new client session and returns the opened session and its information.
	//
	// connectAddr specifies an optional connect address for the session. If valid, the server
	// is expected to drop received packets not sent from this address.
	//
	// The returned [PacketClientSessionInfo] is always valid, even when session creation fails.
	NewSession(ctx context.Context, connectAddr conn.Addr) (PacketClientSession, PacketClientSessionInfo, error)
}

// PacketClientSession handles packing and unpacking of packets for a client session.
type PacketClientSession interface {
	// AppendPack packs the payload into a packet ready for sending and appends it to the buffer.
	// It returns the extended buffer, the destination address of the packed packet, or an error if packing fails.
	//
	// The remaining capacity of b must not overlap payload.
	//
	// If the session is "connected", destAddr must be the zero value.
	//
	// If the session uses a connected socket, sendAddrPort must be the zero value.
	AppendPack(ctx context.Context, b, payload []byte, destAddr conn.Addr) (sendBuf []byte, sendAddrPort netip.AddrPort, err error)

	// UnpackInPlace unpacks the received packet in-place and returns the payload, source address,
	// or an error if unpacking fails.
	//
	// If the session uses a connected socket, recvAddrPort will be the zero value.
	//
	// If the session is "connected", srcAddr must be the zero value.
	UnpackInPlace(recvBuf []byte, recvAddrPort netip.AddrPort) (payload []byte, srcAddr conn.Addr, err error)

	// Close closes the session.
	Close() error
}

// PacketClientSessionInfo contains information about a client session.
type PacketClientSessionInfo struct {
	// Name is the name of the client.
	Name string

	// MaxPacketSize is the maximum size of outgoing packets.
	MaxPacketSize int

	// ListenConfig is the [conn.ListenConfig] for opening unconnected client sockets.
	ListenConfig conn.ListenConfig

	// Dialer is the [conn.Dialer] for opening connected client sockets.
	Dialer conn.Dialer

	// ConnectAddr is the address for the client socket to connect to.
	ConnectAddr conn.Addr
}

// PacketServer handles incoming packet sessions from clients.
type PacketServer[SID comparable] interface {
	// PacketServerInfo returns information about the packet server.
	PacketServerInfo() PacketServerInfo

	// HandlePacket extracts the session ID from the received packet.
	//
	// The returned session ID is then used by the caller to look up the session table.
	// If no matching session is found, [NewSession] should be called to create a new session.
	HandlePacket(recvBuf []byte, recvAddrPort netip.AddrPort) (sid SID, err error)

	// NewSession creates a new session with the given session ID and unpacks the received packet in-place.
	// It returns the server session, session information, payload, destination address, or an error
	// if session creation or unpacking fails.
	NewSession(recvBuf []byte, sid SID) (
		serverSession PacketServerSession,
		serverSessionInfo PacketServerSessionInfo,
		payload []byte, destAddr conn.Addr, err error,
	)
}

// PacketServerInfo contains information about a packet server.
type PacketServerInfo struct {
	// MinNATTimeout is the minimum NAT timeout allowed by the server.
	MinNATTimeout time.Duration
}

// PacketServerSession handles packing and unpacking of packets for a server session.
type PacketServerSession interface {
	// UnpackInPlace unpacks the received packet in-place and returns the payload, destination address,
	// or an error if unpacking fails.
	//
	// If the session is "connected", destAddr must be the zero value.
	UnpackInPlace(recvBuf []byte, recvAddrPort netip.AddrPort) (payload []byte, destAddr conn.Addr, err error)

	// AppendPack packs the payload into a packet ready for sending and appends it to the buffer.
	// It returns the extended buffer, or an error if packing fails.
	//
	// The remaining capacity of b must not overlap payload.
	//
	// If the session is "connected", srcAddr will be the zero value.
	AppendPack(b, payload []byte, srcAddr conn.Addr) (sendBuf []byte, err error)
}

// PacketServerSessionInfo contains information about a server session.
type PacketServerSessionInfo struct {
	// Username identifies the initiator of the session.
	Username string

	// IsConnected indicates whether the session is "connected".
	//
	// If true, received packets not sent from the connected address are dropped.
	IsConnected bool
}

// PacketProxyServerConfig is the configuration for a packet proxy server.
type PacketProxyServerConfig struct {
	// Addr is the destination address.
	Addr conn.Addr

	// IsConnected controls whether to establish "connected" sessions.
	//
	// If true, received packets not sent from Addr are dropped.
	IsConnected bool
}

// NewPacketProxyServer returns a new packet proxy server.
func (c *PacketProxyServerConfig) NewPacketProxyServer() PacketServer[netip.AddrPort] {
	if c.IsConnected {
		return &PacketProxyServerConnected{
			connectAddr: c.Addr,
		}
	}
	return &PacketProxyServer{
		session: PacketProxyServerSession{
			addr: c.Addr,
		},
	}
}

// PacketProxyServer proxies all incoming packet sessions to a fixed destination address.
//
// PacketProxyServer implements [PacketServer].
type PacketProxyServer struct {
	session PacketProxyServerSession
}

// PacketServerInfo implements [PacketServer.PacketServerInfo].
func (*PacketProxyServer) PacketServerInfo() PacketServerInfo {
	return PacketServerInfo{}
}

// HandlePacket implements [PacketServer.HandlePacket].
func (*PacketProxyServer) HandlePacket(_ []byte, recvAddrPort netip.AddrPort) (sid netip.AddrPort, err error) {
	return recvAddrPort, nil
}

// NewSession implements [PacketServer.NewSession].
func (s *PacketProxyServer) NewSession(recvBuf []byte, _ netip.AddrPort) (
	serverSession PacketServerSession,
	serverSessionInfo PacketServerSessionInfo,
	payload []byte, destAddr conn.Addr, err error,
) {
	return &s.session, PacketServerSessionInfo{}, recvBuf, s.session.addr, nil
}

// PacketProxyServerSession passes packets unmodified to a fixed destination address.
//
// PacketProxyServerSession implements [PacketServerSession].
type PacketProxyServerSession struct {
	addr conn.Addr
}

// UnpackInPlace implements [PacketServerSession.UnpackInPlace].
func (s *PacketProxyServerSession) UnpackInPlace(recvBuf []byte, _ netip.AddrPort) (payload []byte, destAddr conn.Addr, err error) {
	return recvBuf, s.addr, nil
}

// AppendPack implements [PacketServerSession.AppendPack].
func (*PacketProxyServerSession) AppendPack(b, payload []byte, _ conn.Addr) (sendBuf []byte, err error) {
	return append(b, payload...), nil
}

// PacketProxyServerConnected is like [PacketProxyServer] but
// drops packets that are not sent from the destination address.
//
// PacketProxyServerConnected implements [PacketServer].
type PacketProxyServerConnected struct {
	connectAddr conn.Addr
}

// PacketServerInfo implements [PacketServer.PacketServerInfo].
func (*PacketProxyServerConnected) PacketServerInfo() PacketServerInfo {
	return PacketServerInfo{}
}

// HandlePacket implements [PacketServer.HandlePacket].
func (*PacketProxyServerConnected) HandlePacket(_ []byte, recvAddrPort netip.AddrPort) (sid netip.AddrPort, err error) {
	return recvAddrPort, nil
}

// NewSession implements [PacketServer.NewSession].
func (s *PacketProxyServerConnected) NewSession(recvBuf []byte, _ netip.AddrPort) (
	serverSession PacketServerSession,
	serverSessionInfo PacketServerSessionInfo,
	payload []byte, destAddr conn.Addr, err error,
) {
	return PacketProxyServerConnectedSession{}, PacketServerSessionInfo{IsConnected: true}, recvBuf, s.connectAddr, nil
}

// PacketProxyServerConnectedSession is like [PacketProxyServerSession] but
// drops packets that are not sent from the destination address.
//
// PacketProxyServerConnectedSession implements [PacketServerSession].
type PacketProxyServerConnectedSession struct{}

// UnpackInPlace implements [PacketServerSession.UnpackInPlace].
func (PacketProxyServerConnectedSession) UnpackInPlace(recvBuf []byte, _ netip.AddrPort) (payload []byte, destAddr conn.Addr, err error) {
	return recvBuf, conn.Addr{}, nil
}

// AppendPack implements [PacketServerSession.AppendPack].
func (PacketProxyServerConnectedSession) AppendPack(b, payload []byte, srcAddr conn.Addr) (sendBuf []byte, err error) {
	return append(b, payload...), nil
}

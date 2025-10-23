package netio

import (
	"context"
	"net/netip"

	"github.com/database64128/shadowsocks-go/cache"
	"github.com/database64128/shadowsocks-go/conn"
)

// MaxUDPPayloadSizeForAddr calculates the maximum unfragmented UDP payload size for the given address
// based on the MTU and address family.
func MaxUDPPayloadSizeForAddr(mtu int, addr netip.Addr) int {
	return MaxUDPPayloadSize(mtu, addr.Is4() || addr.Is4In6())
}

// MaxUDPPayloadSize calculates the maximum unfragmented UDP payload size for the MTU and address family.
func MaxUDPPayloadSize(mtu int, is4 bool) int {
	const (
		IPv4HeaderLength = 20
		IPv6HeaderLength = 40
		UDPHeaderLength  = 8

		// Next Header (1) + Hdr Ext Len (1) + Option Type (1) + Opt Data Len (1) + Jumbo Payload Length (u32be)
		//
		//  1. RFC 2675 - IPv6 Jumbograms
		//  2. RFC 8200 - IPv6 Specification
		JumboPayloadOptionLength = 1 + 1 + 1 + 1 + 4
	)
	if is4 {
		return mtu - IPv4HeaderLength - UDPHeaderLength
	}
	if mtu > 65575 {
		return mtu - IPv6HeaderLength - JumboPayloadOptionLength - UDPHeaderLength
	}
	return mtu - IPv6HeaderLength - UDPHeaderLength
}

// UDPClientConfig is the configuration for a UDP client.
type UDPClientConfig struct {
	// Name is the name of the client.
	Name string

	// Network controls the address family when resolving domain name destination addresses.
	//
	//  - "ip": System default, likely dual-stack.
	//  - "ip4": Resolve to IPv4 addresses.
	//  - "ip6": Resolve to IPv6 addresses.
	Network string

	// MTU is the MTU of the client's designated network path.
	// It serves as a hint for calculating buffer sizes.
	MTU int

	// ListenConfig is the [conn.ListenConfig] for opening unconnected client sockets.
	ListenConfig conn.ListenConfig

	// Dialer is the [conn.Dialer] for opening connected client sockets.
	Dialer conn.Dialer
}

// NewUDPClient returns a new UDP client.
func (c *UDPClientConfig) NewUDPClient() *UDPClient {
	is4 := c.Network == "ip" || c.Network == "ip4"
	return &UDPClient{
		name:          c.Name,
		network:       c.Network,
		maxPacketSize: MaxUDPPayloadSize(c.MTU, is4),
		listenConfig:  c.ListenConfig,
		dialer:        c.Dialer,
	}
}

// UDPClient establishes UDP sessions to servers.
//
// UDPClient implements [PacketClient].
type UDPClient struct {
	name          string
	network       string
	maxPacketSize int
	listenConfig  conn.ListenConfig
	dialer        conn.Dialer
}

var _ PacketClient = (*UDPClient)(nil)

// NewSession implements [PacketClient.NewSession].
func (c *UDPClient) NewSession(ctx context.Context, connectAddr conn.Addr) (PacketClientSession, PacketClientSessionInfo, error) {
	if connectAddr.IsValid() {
		return UDPClientConnectedSession{}, PacketClientSessionInfo{
			Name:          c.name,
			MaxPacketSize: c.maxPacketSize,
			Dialer:        c.dialer,
			ConnectAddr:   connectAddr,
		}, nil
	}
	return &UDPClientSession{network: c.network}, PacketClientSessionInfo{
		Name:          c.name,
		MaxPacketSize: c.maxPacketSize,
		ListenConfig:  c.listenConfig,
	}, nil
}

// UDPClientSession passes UDP packets unmodified.
//
// UDPClientSession implements [PacketClientSession].
type UDPClientSession struct {
	ipByDomain *cache.BoundedCache[string, netip.Addr]
	network    string
}

// AppendPack implements [PacketClientSession.AppendPack].
func (s *UDPClientSession) AppendPack(ctx context.Context, b, payload []byte, destAddr conn.Addr) (sendBuf []byte, sendAddrPort netip.AddrPort, err error) {
	if destAddr.IsIP() {
		sendAddrPort = destAddr.IPPort()
	} else {
		if s.ipByDomain == nil {
			// Initialize the cache with a reasonable size.
			const domainCacheSize = 32
			s.ipByDomain = cache.NewBoundedCache[string, netip.Addr](domainCacheSize)
		}
		domain := destAddr.Domain()
		ip, ok := s.ipByDomain.Get(domain)
		if !ok {
			ip, err = destAddr.ResolveIP(ctx, s.network)
			if err != nil {
				return nil, netip.AddrPort{}, err
			}
			s.ipByDomain.InsertUnchecked(domain, ip)
		}
		sendAddrPort = netip.AddrPortFrom(ip, destAddr.Port())
	}
	return append(b, payload...), sendAddrPort, nil
}

// UnpackInPlace implements [PacketClientSession.UnpackInPlace].
func (*UDPClientSession) UnpackInPlace(recvBuf []byte, recvAddrPort netip.AddrPort) (payload []byte, srcAddr conn.Addr, err error) {
	return recvBuf, conn.AddrFromIPPort(recvAddrPort), nil
}

// Close implements [PacketClientSession.Close].
func (*UDPClientSession) Close() error {
	return nil
}

// UDPClientConnectedSession is like [UDPClientSession] but for "connected" sessions.
//
// UDPClientConnectedSession implements [PacketClientSession].
type UDPClientConnectedSession struct{}

// AppendPack implements [PacketClientSession.AppendPack].
func (UDPClientConnectedSession) AppendPack(_ context.Context, b, payload []byte, _ conn.Addr) (sendBuf []byte, sendAddrPort netip.AddrPort, err error) {
	return append(b, payload...), netip.AddrPort{}, nil
}

// UnpackInPlace implements [PacketClientSession.UnpackInPlace].
func (UDPClientConnectedSession) UnpackInPlace(recvBuf []byte, _ netip.AddrPort) (payload []byte, srcAddr conn.Addr, err error) {
	return recvBuf, conn.Addr{}, nil
}

// Close implements [PacketClientSession.Close].
func (UDPClientConnectedSession) Close() error {
	return nil
}

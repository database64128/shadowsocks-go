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

	// AddressFamilyPreference specifies the preference for IPv4 or IPv6 addresses.
	//
	//  - [AddressFamilyPreferenceDefault]: Resolve without preference ("ip" network).
	//    Use the first resolved IP address.
	//  - [AddressFamilyPreferencePreferIPv6]: Resolve to both IPv6 and IPv4 addresses in parallel.
	//    Prefer the first resolved IPv6 address.
	//  - [AddressFamilyPreferencePreferIPv4]: Resolve to both IPv4 and IPv6 addresses in parallel.
	//    Prefer the first resolved IPv4 address.
	//  - [AddressFamilyPreferenceIPv6Only]: IPv6 addresses only.
	//  - [AddressFamilyPreferenceIPv4Only]: IPv4 addresses only.
	AddressFamilyPreference AddressFamilyPreference

	// Resolver optionally specifies a resolver for resolving domain name destination addresses.
	//
	// If nil, [net.DefaultResolver] is used.
	Resolver conn.Resolver

	// MTU is the MTU of the client's designated network path.
	// It serves as a hint for calculating buffer sizes.
	MTU int

	// SocketConfig is the [conn.UDPSocketConfig] for opening client sockets.
	SocketConfig conn.UDPSocketConfig
}

// NewUDPClient returns a new UDP client.
func (c *UDPClientConfig) NewUDPClient() *UDPClient {
	return &UDPClient{
		name:          c.Name,
		pref:          c.AddressFamilyPreference,
		resolver:      c.Resolver,
		maxPacketSize: MaxUDPPayloadSize(c.MTU, c.AddressFamilyPreference != AddressFamilyPreferenceIPv6Only),
		socketConfig:  c.SocketConfig,
	}
}

// UDPClient establishes UDP sessions to servers.
//
// UDPClient implements [PacketClient].
type UDPClient struct {
	name          string
	pref          AddressFamilyPreference
	resolver      conn.Resolver
	maxPacketSize int
	socketConfig  conn.UDPSocketConfig
}

var _ PacketClient = (*UDPClient)(nil)

// NewSession implements [PacketClient.NewSession].
func (c *UDPClient) NewSession(ctx context.Context, connectAddr conn.Addr) (PacketClientSession, PacketClientSessionInfo, error) {
	if connectAddr.IsValid() {
		return UDPClientConnectedSession{}, PacketClientSessionInfo{
			Name:          c.name,
			MaxPacketSize: c.maxPacketSize,
			SocketConfig:  c.socketConfig,
			ConnectAddr:   connectAddr,
		}, nil
	}
	return &UDPClientSession{
		pref:     c.pref,
		resolver: c.resolver,
	}, PacketClientSessionInfo{
		Name:          c.name,
		MaxPacketSize: c.maxPacketSize,
		SocketConfig:  c.socketConfig,
	}, nil
}

// UDPClientSession passes UDP packets unmodified.
//
// UDPClientSession implements [PacketClientSession].
type UDPClientSession struct {
	ipByDomain *cache.BoundedCache[string, netip.Addr]
	pref       AddressFamilyPreference
	resolver   conn.Resolver
}

// AppendPack implements [PacketClientSession.AppendPack].
func (s *UDPClientSession) AppendPack(ctx context.Context, b, payload []byte, destAddr conn.Addr) (sendBuf []byte, sendAddrPort netip.AddrPort, err error) {
	if destAddr.IsIP() {
		sendAddrPort = destAddr.IPPort()
		if err := s.pref.FilterIP(sendAddrPort.Addr()); err != nil {
			return nil, netip.AddrPort{}, err
		}
	} else {
		if s.ipByDomain == nil {
			// Initialize the cache with a reasonable size.
			const domainCacheSize = 32
			s.ipByDomain = cache.NewBoundedCache[string, netip.Addr](domainCacheSize)
		}
		domain := destAddr.Domain()
		ip, ok := s.ipByDomain.Get(domain)
		if !ok {
			ip, err = ResolveIP(ctx, destAddr, s.pref, s.resolver)
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

package direct

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// DirectUDPClient is a UDP client that makes no changes to the packets.
//
// DirectUDPClient implements [zerocopy.UDPClient].
type DirectUDPClient struct {
	info    zerocopy.UDPClientSessionInfo
	session zerocopy.UDPClientSession
}

// NewDirectUDPClient creates a new UDP client that makes no changes to the packets.
func NewDirectUDPClient(name string, pref netio.AddressFamilyPreference, resolver conn.Resolver, mtu int, socketConfig conn.UDPSocketConfig) *DirectUDPClient {
	return &DirectUDPClient{
		info: zerocopy.UDPClientSessionInfo{
			Name:         name,
			MTU:          mtu,
			SocketConfig: socketConfig,
		},
		session: zerocopy.UDPClientSession{
			MaxPacketSize: zerocopy.MaxPacketSizeForAddr(mtu, netip.IPv4Unspecified()),
			Packer:        NewDirectPacketClientPacker(pref, resolver, mtu),
			Unpacker:      DirectPacketClientUnpacker{},
			Close:         zerocopy.NoopClose,
		},
	}
}

// Info implements [zerocopy.UDPClient.Info].
func (c *DirectUDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{
		Name: c.info.Name,
	}
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (c *DirectUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	return c.info, c.session, nil
}

// ShadowsocksNoneUDPClient is a Shadowsocks none UDP client.
//
// ShadowsocksNoneUDPClient implements [zerocopy.UDPClient].
type ShadowsocksNoneUDPClient struct {
	addr     conn.Addr
	pref     netio.AddressFamilyPreference
	resolver conn.Resolver
	info     zerocopy.UDPClientSessionInfo
}

// NewShadowsocksNoneUDPClient creates a new Shadowsocks none UDP client.
func NewShadowsocksNoneUDPClient(name string, addr conn.Addr, pref netio.AddressFamilyPreference, resolver conn.Resolver, mtu int, socketConfig conn.UDPSocketConfig) *ShadowsocksNoneUDPClient {
	return &ShadowsocksNoneUDPClient{
		addr:     addr,
		pref:     pref,
		resolver: resolver,
		info: zerocopy.UDPClientSessionInfo{
			Name:           name,
			PackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
			MTU:            mtu,
			SocketConfig:   socketConfig,
		},
	}
}

// Info implements [zerocopy.UDPClient.Info].
func (c *ShadowsocksNoneUDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{
		Name:           c.info.Name,
		PackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
	}
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (c *ShadowsocksNoneUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	addrPort, err := netio.ResolveIPPort(ctx, c.addr, c.pref, c.resolver)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to resolve endpoint address: %w", err)
	}
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(c.info.MTU, addrPort.Addr())

	return c.info, zerocopy.UDPClientSession{
		MaxPacketSize: maxPacketSize,
		Packer:        NewShadowsocksNonePacketClientPacker(addrPort, maxPacketSize),
		Unpacker:      NewShadowsocksNonePacketClientUnpacker(addrPort),
		Close:         zerocopy.NoopClose,
	}, nil
}

// Socks5UDPClientConfig contains configuration options for a SOCKS5 UDP client.
type Socks5UDPClientConfig struct {
	// Logger is the logger used for logging.
	Logger *tslog.Logger

	// Name is the name of the SOCKS5 client.
	Name string

	// StreamDialer is the TCP dialer for establishing the initial TCP connection to the SOCKS5 server.
	StreamDialer netio.StreamDialer

	// Addr is the SOCKS5 server's TCP address.
	Addr conn.Addr

	// AddressFamilyPreference specifies the preference for IPv4 or IPv6 addresses
	// when resolving the server's UDP bound address.
	AddressFamilyPreference netio.AddressFamilyPreference

	// Resolver is the resolver used to resolve the server's UDP bound address.
	//
	// If nil, the default resolver is used.
	Resolver conn.Resolver

	// MTU is the MTU of the client's designated network path.
	MTU int

	// SocketConfig is the [conn.UDPSocketConfig] for opening client sockets.
	SocketConfig conn.UDPSocketConfig

	// AuthMsg is the serialized username/password authentication message.
	AuthMsg []byte
}

// NewClient creates a new SOCKS5 UDP client.
func (c *Socks5UDPClientConfig) NewClient() zerocopy.UDPClient {
	client := Socks5UDPClient{
		logger:       c.Logger,
		streamDialer: c.StreamDialer,
		addr:         c.Addr,
		pref:         c.AddressFamilyPreference,
		resolver:     c.Resolver,
		info: zerocopy.UDPClientSessionInfo{
			Name:           c.Name,
			PackerHeadroom: Socks5PacketClientMessageHeadroom,
			MTU:            c.MTU,
			SocketConfig:   c.SocketConfig,
		},
	}

	if len(c.AuthMsg) > 0 {
		return &Socks5AuthUDPClient{
			plainClient: client,
			authMsg:     c.AuthMsg,
		}
	}

	return &client
}

// Socks5UDPClient is a SOCKS5 UDP client.
//
// Socks5UDPClient implements [zerocopy.UDPClient].
type Socks5UDPClient struct {
	logger       *tslog.Logger
	streamDialer netio.StreamDialer
	addr         conn.Addr
	pref         netio.AddressFamilyPreference
	resolver     conn.Resolver
	info         zerocopy.UDPClientSessionInfo
}

// Info implements [zerocopy.UDPClient.Info].
func (c *Socks5UDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{
		Name:           c.info.Name,
		PackerHeadroom: Socks5PacketClientMessageHeadroom,
	}
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (c *Socks5UDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	tc, err := c.streamDialer.DialStream(ctx, c.addr, nil)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to dial SOCKS5 server: %w", err)
	}

	addr, err := socks5.ClientUDPAssociate(tc, conn.Addr{})
	if err != nil {
		_ = tc.Close()
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to request UDP association: %w", err)
	}

	session, err := c.newSession(ctx, tc, addr)
	return c.info, session, err
}

func (c *Socks5UDPClient) newSession(ctx context.Context, tc netio.Conn, addr conn.Addr) (zerocopy.UDPClientSession, error) {
	addrPort, err := netio.ResolveIPPort(ctx, addr, c.pref, c.resolver)
	if err != nil {
		_ = tc.Close()
		return zerocopy.UDPClientSession{}, fmt.Errorf("failed to resolve endpoint address: %w", err)
	}
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(c.info.MTU, addrPort.Addr())

	go func() {
		defer tc.Close()
		b := make([]byte, 1)
		_, err := tc.Read(b)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			c.logger.Warn("Failed to keep SOCKS5 TCP connection open for UDP association",
				slog.String("client", c.info.Name),
				tslog.Err(err),
			)
		}
	}()

	return zerocopy.UDPClientSession{
		MaxPacketSize: maxPacketSize,
		Packer:        NewSocks5PacketClientPacker(addrPort, maxPacketSize),
		Unpacker:      NewSocks5PacketClientUnpacker(addrPort),
		Close: func() error {
			return tc.SetReadDeadline(conn.ALongTimeAgo)
		},
	}, nil
}

// Socks5AuthUDPClient is like [Socks5UDPClient], but uses username/password authentication.
//
// Socks5AuthUDPClient implements [zerocopy.UDPClient].
type Socks5AuthUDPClient struct {
	plainClient Socks5UDPClient
	authMsg     []byte
}

// Info implements [zerocopy.UDPClient.Info].
func (c *Socks5AuthUDPClient) Info() zerocopy.UDPClientInfo {
	return c.plainClient.Info()
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (c *Socks5AuthUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	tc, err := c.plainClient.streamDialer.DialStream(ctx, c.plainClient.addr, nil)
	if err != nil {
		return c.plainClient.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to dial SOCKS5 server: %w", err)
	}

	addr, err := socks5.ClientUDPAssociateUsernamePassword(tc, c.authMsg, conn.Addr{})
	if err != nil {
		_ = tc.Close()
		return c.plainClient.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to request UDP association: %w", err)
	}

	session, err := c.plainClient.newSession(ctx, tc, addr)
	return c.plainClient.info, session, err
}

// DirectUDPNATServer is a UDP NAT server that makes no changes to the packets.
//
// DirectUDPNATServer implements [zerocopy.UDPNATServer].
type DirectUDPNATServer struct {
	p *DirectPacketServerPackUnpacker
}

// NewDirectUDPNATServer creates a new UDP NAT server that makes no changes to the packets.
func NewDirectUDPNATServer(targetAddr conn.Addr, targetAddrOnly bool) *DirectUDPNATServer {
	return &DirectUDPNATServer{
		p: NewDirectPacketServerPackUnpacker(targetAddr, targetAddrOnly),
	}
}

// Info implements [zerocopy.UDPNATServer.Info].
func (s *DirectUDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{}
}

// NewUnpacker implements [zerocopy.UDPNATServer.NewUnpacker].
func (s *DirectUDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return s.p, nil
}

// ShadowsocksNoneUDPNATServer is a Shadowsocks none UDP NAT server.
//
// ShadowsocksNoneUDPNATServer implements [zerocopy.UDPNATServer].
type ShadowsocksNoneUDPNATServer struct{}

// Info implements [zerocopy.UDPNATServer.Info].
func (ShadowsocksNoneUDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{
		UnpackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
	}
}

// NewUnpacker implements [zerocopy.UDPNATServer.NewUnpacker].
func (ShadowsocksNoneUDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return &ShadowsocksNonePacketServerUnpacker{}, nil
}

// Socks5UDPNATServer is a SOCKS5 UDP NAT server.
//
// Socks5UDPNATServer implements [zerocopy.UDPNATServer].
type Socks5UDPNATServer struct{}

// Info implements [zerocopy.UDPNATServer.Info].
func (Socks5UDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{
		UnpackerHeadroom: Socks5PacketClientMessageHeadroom,
	}
}

// NewUnpacker implements [zerocopy.UDPNATServer.NewUnpacker].
func (Socks5UDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return &Socks5PacketServerUnpacker{}, nil
}

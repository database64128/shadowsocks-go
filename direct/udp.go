package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// DirectUDPClient is a UDP client that makes no changes to the packets.
//
// DirectUDPClient implements [zerocopy.UDPClient].
type DirectUDPClient struct {
	info    zerocopy.UDPClientSessionInfo
	session zerocopy.UDPClientSession
}

// NewDirectUDPClient creates a new UDP client that makes no changes to the packets.
func NewDirectUDPClient(name, network string, mtu int, listenConfig conn.ListenConfig) *DirectUDPClient {
	return &DirectUDPClient{
		info: zerocopy.UDPClientSessionInfo{
			Name:         name,
			MTU:          mtu,
			ListenConfig: listenConfig,
		},
		session: zerocopy.UDPClientSession{
			MaxPacketSize: zerocopy.MaxPacketSizeForAddr(mtu, netip.IPv4Unspecified()),
			Packer:        NewDirectPacketClientPacker(network, mtu),
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
	network string
	addr    conn.Addr
	info    zerocopy.UDPClientSessionInfo
}

// NewShadowsocksNoneUDPClient creates a new Shadowsocks none UDP client.
func NewShadowsocksNoneUDPClient(name, network string, addr conn.Addr, mtu int, listenConfig conn.ListenConfig) *ShadowsocksNoneUDPClient {
	return &ShadowsocksNoneUDPClient{
		network: network,
		addr:    addr,
		info: zerocopy.UDPClientSessionInfo{
			Name:           name,
			PackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
			MTU:            mtu,
			ListenConfig:   listenConfig,
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
	addrPort, err := c.addr.ResolveIPPort(ctx, c.network)
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
	Logger *zap.Logger

	// Name is the name of the SOCKS5 client.
	Name string

	// Network controls the address family when resolving the server's TCP address.
	//
	// - "tcp": System default, likely dual-stack.
	// - "tcp4": Resolve to IPv4 addresses.
	// - "tcp6": Resolve to IPv6 addresses.
	NetworkTCP string

	// NetworkIP controls the address family when resolving the server's UDP bound address.
	//
	// - "ip": System default, likely dual-stack.
	// - "ip4": Resolve to IPv4 addresses.
	// - "ip6": Resolve to IPv6 addresses.
	NetworkIP string

	// Address is the SOCKS5 server's TCP address.
	Address string

	// Dialer is the dialer used to establish TCP connections.
	Dialer conn.Dialer

	// MTU is the MTU of the client's designated network path.
	MTU int

	// ListenConfig is the [conn.ListenConfig] for opening client sockets.
	ListenConfig conn.ListenConfig

	// AuthMsg is the serialized username/password authentication message.
	AuthMsg []byte
}

// NewClient creates a new SOCKS5 UDP client.
func (c *Socks5UDPClientConfig) NewClient() zerocopy.UDPClient {
	client := Socks5UDPClient{
		logger:     c.Logger,
		networkTCP: c.NetworkTCP,
		networkIP:  c.NetworkIP,
		address:    c.Address,
		dialer:     c.Dialer,
		info: zerocopy.UDPClientSessionInfo{
			Name:           c.Name,
			PackerHeadroom: Socks5PacketClientMessageHeadroom,
			MTU:            c.MTU,
			ListenConfig:   c.ListenConfig,
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
	logger     *zap.Logger
	networkTCP string
	networkIP  string
	address    string
	dialer     conn.Dialer
	info       zerocopy.UDPClientSessionInfo
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
	tc, err := c.dialer.DialTCP(ctx, c.networkTCP, c.address, nil)
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

func (c *Socks5UDPClient) newSession(ctx context.Context, tc *net.TCPConn, addr conn.Addr) (zerocopy.UDPClientSession, error) {
	addrPort, err := addr.ResolveIPPort(ctx, c.networkIP)
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
				zap.String("client", c.info.Name),
				zap.Error(err),
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
	tc, err := c.plainClient.dialer.DialTCP(ctx, c.plainClient.networkTCP, c.plainClient.address, nil)
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

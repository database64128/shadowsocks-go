package direct

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// DirectUDPClient implements the zerocopy UDPClient interface.
type DirectUDPClient struct {
	info    zerocopy.UDPClientInfo
	session zerocopy.UDPClientSession
}

// NewDirectUDPClient creates a new UDP client that sends packets directly.
func NewDirectUDPClient(name, network string, mtu int, listenConfig conn.ListenConfig) *DirectUDPClient {
	return &DirectUDPClient{
		info: zerocopy.UDPClientInfo{
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

// Info implements the zerocopy.UDPClient Info method.
func (c *DirectUDPClient) Info() zerocopy.UDPClientInfo {
	return c.info
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *DirectUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientInfo, zerocopy.UDPClientSession, error) {
	return c.info, c.session, nil
}

// ShadowsocksNoneUDPClient implements the zerocopy UDPClient interface.
type ShadowsocksNoneUDPClient struct {
	network string
	addr    conn.Addr
	info    zerocopy.UDPClientInfo
}

// NewShadowsocksNoneUDPClient creates a new Shadowsocks none UDP client.
func NewShadowsocksNoneUDPClient(name, network string, addr conn.Addr, mtu int, listenConfig conn.ListenConfig) *ShadowsocksNoneUDPClient {
	return &ShadowsocksNoneUDPClient{
		network: network,
		addr:    addr,
		info: zerocopy.UDPClientInfo{
			Name:           name,
			PackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
			MTU:            mtu,
			ListenConfig:   listenConfig,
		},
	}
}

// Info implements the zerocopy.UDPClient Info method.
func (c *ShadowsocksNoneUDPClient) Info() zerocopy.UDPClientInfo {
	return c.info
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *ShadowsocksNoneUDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientInfo, zerocopy.UDPClientSession, error) {
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

// Socks5UDPClient implements the zerocopy UDPClient interface.
type Socks5UDPClient struct {
	logger     *zap.Logger
	networkTCP string
	networkIP  string
	address    string
	dialer     conn.Dialer
	info       zerocopy.UDPClientInfo
}

// NewSocks5UDPClient creates a new SOCKS5 UDP client.
func NewSocks5UDPClient(logger *zap.Logger, name, networkTCP, networkIP, address string, dialer conn.Dialer, mtu int, listenConfig conn.ListenConfig) *Socks5UDPClient {
	return &Socks5UDPClient{
		logger:     logger,
		networkTCP: networkTCP,
		networkIP:  networkIP,
		address:    address,
		dialer:     dialer,
		info: zerocopy.UDPClientInfo{
			Name:           name,
			PackerHeadroom: Socks5PacketClientMessageHeadroom,
			MTU:            mtu,
			ListenConfig:   listenConfig,
		},
	}
}

// Info implements the zerocopy.UDPClient Info method.
func (c *Socks5UDPClient) Info() zerocopy.UDPClientInfo {
	return c.info
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *Socks5UDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientInfo, zerocopy.UDPClientSession, error) {
	tc, err := c.dialer.DialTCP(ctx, c.networkTCP, c.address, nil)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, err
	}

	addr, err := socks5.ClientUDPAssociate(tc, conn.Addr{})
	if err != nil {
		tc.Close()
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to request UDP association: %w", err)
	}

	addrPort, err := addr.ResolveIPPort(ctx, c.networkIP)
	if err != nil {
		tc.Close()
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to resolve endpoint address: %w", err)
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

	return c.info, zerocopy.UDPClientSession{
		MaxPacketSize: maxPacketSize,
		Packer:        NewSocks5PacketClientPacker(addrPort, maxPacketSize),
		Unpacker:      NewSocks5PacketClientUnpacker(addrPort),
		Close: func() error {
			return tc.SetReadDeadline(conn.ALongTimeAgo)
		},
	}, nil
}

// DirectUDPNATServer implements the zerocopy UDPNATServer interface.
type DirectUDPNATServer struct {
	p *DirectPacketServerPackUnpacker
}

func NewDirectUDPNATServer(targetAddr conn.Addr, targetAddrOnly bool) *DirectUDPNATServer {
	return &DirectUDPNATServer{
		p: NewDirectPacketServerPackUnpacker(targetAddr, targetAddrOnly),
	}
}

// Info implements the zerocopy.UDPNATServer Info method.
func (s *DirectUDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{}
}

// NewUnpacker implements the zerocopy.UDPNATServer NewUnpacker method.
func (s *DirectUDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return s.p, nil
}

// ShadowsocksNoneUDPNATServer implements the zerocopy UDPNATServer interface.
type ShadowsocksNoneUDPNATServer struct{}

// Info implements the zerocopy.UDPNATServer Info method.
func (ShadowsocksNoneUDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{
		UnpackerHeadroom: ShadowsocksNonePacketClientMessageHeadroom,
	}
}

// NewUnpacker implements the zerocopy.UDPNATServer NewUnpacker method.
func (ShadowsocksNoneUDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return &ShadowsocksNonePacketServerUnpacker{}, nil
}

// Socks5UDPNATServer implements the zerocopy UDPNATServer interface.
type Socks5UDPNATServer struct{}

// Info implements the zerocopy.UDPNATServer Info method.
func (Socks5UDPNATServer) Info() zerocopy.UDPNATServerInfo {
	return zerocopy.UDPNATServerInfo{
		UnpackerHeadroom: Socks5PacketClientMessageHeadroom,
	}
}

// NewUnpacker implements the zerocopy.UDPNATServer NewUnpacker method.
func (Socks5UDPNATServer) NewUnpacker() (zerocopy.ServerUnpacker, error) {
	return &Socks5PacketServerUnpacker{}, nil
}

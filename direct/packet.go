package direct

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// DirectPacketClientPacker packs packets for direct connection.
//
// DirectPacketClientPacker implements the zerocopy ClientPacker interface.
type DirectPacketClientPacker struct {
	// cachedDomain caches the last used domain target to avoid excessive DNS lookups.
	cachedDomain string

	// cachedDomainIP is the last used domain target's resolved IP address.
	cachedDomainIP netip.Addr

	// network controls the address family of a domain target's resolved IP address.
	network string

	// mtu is used in the PackInPlace method to determine whether the payload is too big.
	mtu int
}

// NewDirectPacketClientPacker creates a packet packer for direct connection.
func NewDirectPacketClientPacker(network string, mtu int) *DirectPacketClientPacker {
	return &DirectPacketClientPacker{
		network: network,
		mtu:     mtu,
	}
}

// ClientPackerInfo implements the zerocopy.ClientPacker ClientPackerInfo method.
func (DirectPacketClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return zerocopy.ClientPackerInfo{}
}

func (p *DirectPacketClientPacker) updateDomainIPCache(ctx context.Context, targetAddr conn.Addr) error {
	if p.cachedDomain != targetAddr.Domain() {
		ip, err := targetAddr.ResolveIP(ctx, p.network)
		if err != nil {
			return err
		}
		p.cachedDomain = targetAddr.Domain()
		p.cachedDomainIP = ip
	}
	return nil
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *DirectPacketClientPacker) PackInPlace(ctx context.Context, b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	if targetAddr.IsIP() {
		destAddrPort = targetAddr.IPPort()
	} else {
		err = p.updateDomainIPCache(ctx, targetAddr)
		if err != nil {
			return
		}
		destAddrPort = netip.AddrPortFrom(p.cachedDomainIP, targetAddr.Port())
	}
	packetStart = payloadStart
	packetLen = payloadLen
	maxPacketLen := zerocopy.MaxPacketSizeForAddr(p.mtu, destAddrPort.Addr())
	if packetLen > maxPacketLen {
		err = zerocopy.ErrPayloadTooBig
	}
	return
}

// DirectPacketClientUnpacker unpacks packets from direct connection.
//
// DirectPacketClientUnpacker implements the zerocopy ClientUnpacker interface.
type DirectPacketClientUnpacker struct{}

// ClientUnpackerInfo implements the zerocopy.ClientUnpacker ClientUnpackerInfo method.
func (DirectPacketClientUnpacker) ClientUnpackerInfo() zerocopy.ClientUnpackerInfo {
	return zerocopy.ClientUnpackerInfo{}
}

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (DirectPacketClientUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddr netip.AddrPort, payloadStart, payloadLen int, err error) {
	payloadSourceAddr = packetSourceAddrPort
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

type DirectPacketServerPackUnpacker struct {
	// targetAddr is the address to which packets are forwarded by the direct server.
	targetAddr conn.Addr

	// targetAddrOnly controls whether to discard packets from non-target sources.
	targetAddrOnly bool
}

// NewDirectPacketServerPackUnpacker creates a zerocopy.ServerPackUnpacker that forwards packets to the specified target address.
func NewDirectPacketServerPackUnpacker(targetAddr conn.Addr, targetAddrOnly bool) *DirectPacketServerPackUnpacker {
	return &DirectPacketServerPackUnpacker{
		targetAddr:     targetAddr,
		targetAddrOnly: targetAddrOnly,
	}
}

// ServerPackerInfo implements the zerocopy.ServerPacker ServerPackerInfo method.
func (DirectPacketServerPackUnpacker) ServerPackerInfo() zerocopy.ServerPackerInfo {
	return zerocopy.ServerPackerInfo{}
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (p *DirectPacketServerPackUnpacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	packetStart = payloadStart
	packetLen = payloadLen
	if packetLen > maxPacketLen {
		err = zerocopy.ErrPayloadTooBig
	}
	if p.targetAddrOnly && !conn.AddrPortMappedEqual(sourceAddrPort, p.targetAddr.IPPort()) {
		err = fmt.Errorf("dropped packet from non-target source %s", sourceAddrPort)
	}
	return
}

// ServerUnpackerInfo implements the zerocopy.ServerUnpacker ServerUnpackerInfo method.
func (DirectPacketServerPackUnpacker) ServerUnpackerInfo() zerocopy.ServerUnpackerInfo {
	return zerocopy.ServerUnpackerInfo{}
}

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *DirectPacketServerPackUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	targetAddr = p.targetAddr
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

// NewPacker implements the zerocopy.ServerUnpacker NewPacker method.
func (p *DirectPacketServerPackUnpacker) NewPacker() (zerocopy.ServerPacker, error) {
	return p, nil
}

// ShadowsocksNonePacketClientMessageHeadroom is the headroom required by a Shadowsocks none client message.
var ShadowsocksNonePacketClientMessageHeadroom = zerocopy.Headroom{
	Front: socks5.MaxAddrLen,
	Rear:  0,
}

// ShadowsocksNonePacketServerMessageHeadroom is the headroom required by a Shadowsocks none server message.
var ShadowsocksNonePacketServerMessageHeadroom = zerocopy.Headroom{
	Front: socks5.IPv6AddrLen,
	Rear:  0,
}

// ShadowsocksNonePacketClientPacker implements the zerocopy ClientPacker interface.
type ShadowsocksNonePacketClientPacker struct {
	// serverAddrPort is the Shadowsocks none server's IP and port.
	serverAddrPort netip.AddrPort

	// maxPacketSize is the maximum allowed size of a packed packet.
	// The value is calculated from MTU and server address family.
	maxPacketSize int
}

// NewShadowsocksNonePacketClientPacker creates a Shadowsocks none packet client packer.
func NewShadowsocksNonePacketClientPacker(serverAddrPort netip.AddrPort, maxPacketSize int) *ShadowsocksNonePacketClientPacker {
	return &ShadowsocksNonePacketClientPacker{
		serverAddrPort: serverAddrPort,
		maxPacketSize:  maxPacketSize,
	}
}

// ClientPackerInfo implements the zerocopy.ClientPacker ClientPackerInfo method.
func (ShadowsocksNonePacketClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return zerocopy.ClientPackerInfo{
		Headroom: ShadowsocksNonePacketClientMessageHeadroom,
	}
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *ShadowsocksNonePacketClientPacker) PackInPlace(ctx context.Context, b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	destAddrPort = p.serverAddrPort
	packetStart = payloadStart - targetAddrLen
	packetLen = payloadLen + targetAddrLen
	if packetLen > p.maxPacketSize {
		err = zerocopy.ErrPayloadTooBig
	}
	socks5.WriteAddrFromConnAddr(b[packetStart:], targetAddr)
	return
}

// ShadowsocksNonePacketClientUnpacker implements the zerocopy ClientUnpacker interface.
type ShadowsocksNonePacketClientUnpacker struct {
	// serverAddrPort is the Shadowsocks none server's IP and port.
	serverAddrPort netip.AddrPort
}

// NewShadowsocksNonePacketClientUnpacker creates a Shadowsocks none packet client unpacker.
func NewShadowsocksNonePacketClientUnpacker(serverAddrPort netip.AddrPort) *ShadowsocksNonePacketClientUnpacker {
	return &ShadowsocksNonePacketClientUnpacker{
		serverAddrPort: serverAddrPort,
	}
}

// ClientUnpackerInfo implements the zerocopy.ClientUnpacker ClientUnpackerInfo method.
func (ShadowsocksNonePacketClientUnpacker) ClientUnpackerInfo() zerocopy.ClientUnpackerInfo {
	return zerocopy.ClientUnpackerInfo{
		Headroom: ShadowsocksNonePacketServerMessageHeadroom,
	}
}

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketClientUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
	if !conn.AddrPortMappedEqual(packetSourceAddrPort, p.serverAddrPort) {
		err = fmt.Errorf("dropped packet from non-server source %s", packetSourceAddrPort)
		return
	}
	var payloadSourceAddrLen int
	payloadSourceAddrPort, payloadSourceAddrLen, err = socks5.AddrPortFromSlice(b[packetStart : packetStart+packetLen])
	payloadStart = packetStart + payloadSourceAddrLen
	payloadLen = packetLen - payloadSourceAddrLen
	return
}

// ShadowsocksNonePacketServerPacker implements the zerocopy ServerPacker interface.
type ShadowsocksNonePacketServerPacker struct{}

// ServerPackerInfo implements the zerocopy.ServerPacker ServerPackerInfo method.
func (ShadowsocksNonePacketServerPacker) ServerPackerInfo() zerocopy.ServerPackerInfo {
	return zerocopy.ServerPackerInfo{
		Headroom: ShadowsocksNonePacketServerMessageHeadroom,
	}
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (ShadowsocksNonePacketServerPacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	packetStart = payloadStart - targetAddrLen
	packetLen = payloadLen + targetAddrLen
	if packetLen > maxPacketLen {
		err = zerocopy.ErrPayloadTooBig
	}
	socks5.WriteAddrFromAddrPort(b[packetStart:], sourceAddrPort)
	return
}

// ShadowsocksNonePacketServerUnpacker implements the zerocopy Unpacker interface.
type ShadowsocksNonePacketServerUnpacker struct {
	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// ServerUnpackerInfo implements the zerocopy.ServerUnpacker ServerUnpackerInfo method.
func (ShadowsocksNonePacketServerUnpacker) ServerUnpackerInfo() zerocopy.ServerUnpackerInfo {
	return zerocopy.ServerUnpackerInfo{
		Headroom: ShadowsocksNonePacketClientMessageHeadroom,
	}
}

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketServerUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	var targetAddrLen int
	targetAddr, targetAddrLen, p.cachedDomain, err = socks5.ConnAddrFromSliceWithDomainCache(b[packetStart:packetStart+packetLen], p.cachedDomain)
	payloadStart = packetStart + targetAddrLen
	payloadLen = packetLen - targetAddrLen
	return
}

// NewPacker implements the zerocopy.ServerUnpacker NewPacker method.
func (ShadowsocksNonePacketServerUnpacker) NewPacker() (zerocopy.ServerPacker, error) {
	return ShadowsocksNonePacketServerPacker{}, nil
}

// Socks5PacketClientMessageHeadroom is the headroom required by a SOCKS5 client message.
var Socks5PacketClientMessageHeadroom = zerocopy.Headroom{
	Front: 3 + socks5.MaxAddrLen,
	Rear:  0,
}

// Socks5PacketServerMessageHeadroom is the headroom required by a SOCKS5 server message.
var Socks5PacketServerMessageHeadroom = zerocopy.Headroom{
	Front: 3 + socks5.IPv6AddrLen,
	Rear:  0,
}

// Socks5PacketClientPacker implements the zerocopy ClientPacker interface.
type Socks5PacketClientPacker struct {
	// serverAddrPort is the SOCKS5 server's IP and port.
	serverAddrPort netip.AddrPort

	// maxPacketSize is the maximum allowed size of a packed packet.
	// The value is calculated from MTU and server address family.
	maxPacketSize int
}

// NewSocks5PacketClientPacker creates a SOCKS5 packet client packer.
func NewSocks5PacketClientPacker(serverAddrPort netip.AddrPort, maxPacketSize int) *Socks5PacketClientPacker {
	return &Socks5PacketClientPacker{
		serverAddrPort: serverAddrPort,
		maxPacketSize:  maxPacketSize,
	}
}

// ClientPackerInfo implements the zerocopy.ClientPacker ClientPackerInfo method.
func (Socks5PacketClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return zerocopy.ClientPackerInfo{
		Headroom: Socks5PacketClientMessageHeadroom,
	}
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *Socks5PacketClientPacker) PackInPlace(ctx context.Context, b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	destAddrPort = p.serverAddrPort
	packetStart = payloadStart - targetAddrLen - 3
	packetLen = payloadLen + targetAddrLen + 3
	if packetLen > p.maxPacketSize {
		err = zerocopy.ErrPayloadTooBig
	}
	socks5.WritePacketHeader(b[packetStart:])
	socks5.WriteAddrFromConnAddr(b[packetStart+3:], targetAddr)
	return
}

// Socks5PacketClientUnpacker implements the zerocopy Unpacker interface.
type Socks5PacketClientUnpacker struct {
	// serverAddrPort is the SOCKS5 server's IP and port.
	serverAddrPort netip.AddrPort
}

// NewSocks5PacketClientUnpacker creates a SOCKS5 packet client unpacker.
func NewSocks5PacketClientUnpacker(serverAddrPort netip.AddrPort) *Socks5PacketClientUnpacker {
	return &Socks5PacketClientUnpacker{
		serverAddrPort: serverAddrPort,
	}
}

// ClientUnpackerInfo implements the zerocopy.ClientUnpacker ClientUnpackerInfo method.
func (Socks5PacketClientUnpacker) ClientUnpackerInfo() zerocopy.ClientUnpackerInfo {
	return zerocopy.ClientUnpackerInfo{
		Headroom: Socks5PacketServerMessageHeadroom,
	}
}

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *Socks5PacketClientUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
	if !conn.AddrPortMappedEqual(packetSourceAddrPort, p.serverAddrPort) {
		err = fmt.Errorf("dropped packet from non-server source %s", packetSourceAddrPort)
		return
	}

	if packetLen < 3 {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	pkt := b[packetStart : packetStart+packetLen]
	err = socks5.ValidatePacketHeader(pkt)
	if err != nil {
		return
	}

	var payloadSourceAddrLen int
	payloadSourceAddrPort, payloadSourceAddrLen, err = socks5.AddrPortFromSlice(pkt[3:])
	payloadStart = packetStart + payloadSourceAddrLen + 3
	payloadLen = packetLen - payloadSourceAddrLen - 3
	return
}

// Socks5PacketServerPacker implements the zerocopy ServerPacker interface.
type Socks5PacketServerPacker struct{}

// ServerPackerInfo implements the zerocopy.ServerPacker ServerPackerInfo method.
func (Socks5PacketServerPacker) ServerPackerInfo() zerocopy.ServerPackerInfo {
	return zerocopy.ServerPackerInfo{
		Headroom: Socks5PacketServerMessageHeadroom,
	}
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (Socks5PacketServerPacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	packetStart = payloadStart - targetAddrLen - 3
	packetLen = payloadLen + targetAddrLen + 3
	if packetLen > maxPacketLen {
		err = zerocopy.ErrPayloadTooBig
	}
	socks5.WritePacketHeader(b[packetStart:])
	socks5.WriteAddrFromAddrPort(b[packetStart+3:], sourceAddrPort)
	return
}

// Socks5PacketServerUnpacker implements the zerocopy Unpacker interface.
type Socks5PacketServerUnpacker struct {
	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// ServerUnpackerInfo implements the zerocopy.ServerUnpacker ServerUnpackerInfo method.
func (Socks5PacketServerUnpacker) ServerUnpackerInfo() zerocopy.ServerUnpackerInfo {
	return zerocopy.ServerUnpackerInfo{
		Headroom: Socks5PacketClientMessageHeadroom,
	}
}

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *Socks5PacketServerUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	if packetLen < 3 {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	pkt := b[packetStart : packetStart+packetLen]
	err = socks5.ValidatePacketHeader(pkt)
	if err != nil {
		return
	}

	var targetAddrLen int
	targetAddr, targetAddrLen, p.cachedDomain, err = socks5.ConnAddrFromSliceWithDomainCache(pkt[3:], p.cachedDomain)
	payloadStart = packetStart + targetAddrLen + 3
	payloadLen = packetLen - targetAddrLen - 3
	return
}

// NewPacker implements the zerocopy.ServerUnpacker NewPacker method.
func (Socks5PacketServerUnpacker) NewPacker() (zerocopy.ServerPacker, error) {
	return Socks5PacketServerPacker{}, nil
}

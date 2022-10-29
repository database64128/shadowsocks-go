package direct

import (
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// DirectPacketClientPackUnpacker packs and unpacks packets for direct connection.
//
// DirectPacketClientPackUnpacker implements the zerocopy ClientPacker and Unpacker interfaces.
type DirectPacketClientPackUnpacker struct {
	zerocopy.ZeroHeadroom

	// cachedDomain caches the last used domain target to avoid excessive DNS lookups.
	cachedDomain string

	// cachedDomainIP is the last used domain target's resolved IP address.
	cachedDomainIP netip.Addr

	// mtu is used in the PackInPlace method to determine whether the payload is too big.
	mtu int
}

// NewDirectPacketClientPackUnpacker creates a zerocopy.ClientPackUnpacker for direct connection.
func NewDirectPacketClientPackUnpacker(mtu int) *DirectPacketClientPackUnpacker {
	return &DirectPacketClientPackUnpacker{
		mtu: mtu,
	}
}

func (p *DirectPacketClientPackUnpacker) updateDomainIPCache(targetAddr conn.Addr) error {
	if p.cachedDomain != targetAddr.Domain() {
		ip, err := targetAddr.ResolveIP()
		if err != nil {
			return err
		}
		p.cachedDomain = targetAddr.Domain()
		p.cachedDomainIP = ip
	}
	return nil
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *DirectPacketClientPackUnpacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	if targetAddr.IsIP() {
		destAddrPort = targetAddr.IPPort()
	} else {
		err = p.updateDomainIPCache(targetAddr)
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

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *DirectPacketClientPackUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddr netip.AddrPort, payloadStart, payloadLen int, err error) {
	payloadSourceAddr = packetSourceAddrPort
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

type DirectPacketServerPackUnpacker struct {
	zerocopy.ZeroHeadroom

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

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *DirectPacketServerPackUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	targetAddr = p.targetAddr
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

// ShadowsocksNonePacketClientMessageHeadroom defines the headroom required by a client message.
//
// ShadowsocksNonePacketClientMessageHeadroom implements the zerocopy Headroom interface.
type ShadowsocksNonePacketClientMessageHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (ShadowsocksNonePacketClientMessageHeadroom) FrontHeadroom() int {
	return socks5.MaxAddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (ShadowsocksNonePacketClientMessageHeadroom) RearHeadroom() int {
	return 0
}

// ShadowsocksNonePacketServerMessageHeadroom defines the headroom required by a server message.
//
// ShadowsocksNonePacketServerMessageHeadroom implements the zerocopy Headroom interface.
type ShadowsocksNonePacketServerMessageHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (ShadowsocksNonePacketServerMessageHeadroom) FrontHeadroom() int {
	return socks5.IPv6AddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (ShadowsocksNonePacketServerMessageHeadroom) RearHeadroom() int {
	return 0
}

// ShadowsocksNonePacketClientPacker implements the zerocopy ClientPacker interface.
type ShadowsocksNonePacketClientPacker struct {
	ShadowsocksNonePacketClientMessageHeadroom

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

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *ShadowsocksNonePacketClientPacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
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
	ShadowsocksNonePacketServerMessageHeadroom

	// serverAddrPort is the Shadowsocks none server's IP and port.
	serverAddrPort netip.AddrPort
}

// NewShadowsocksNonePacketClientUnpacker creates a Shadowsocks none packet client unpacker.
func NewShadowsocksNonePacketClientUnpacker(serverAddrPort netip.AddrPort) *ShadowsocksNonePacketClientUnpacker {
	return &ShadowsocksNonePacketClientUnpacker{
		serverAddrPort: serverAddrPort,
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
type ShadowsocksNonePacketServerPacker struct {
	ShadowsocksNonePacketServerMessageHeadroom
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
	ShadowsocksNonePacketClientMessageHeadroom

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketServerUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	var targetAddrLen int
	targetAddr, targetAddrLen, p.cachedDomain, err = socks5.ConnAddrFromSliceWithDomainCache(b[packetStart:packetStart+packetLen], p.cachedDomain)
	payloadStart = packetStart + targetAddrLen
	payloadLen = packetLen - targetAddrLen
	return
}

// Socks5PacketClientMessageHeadroom defines the headroom required by a client message.
//
// Socks5PacketClientMessageHeadroom implements the zerocopy Headroom interface.
type Socks5PacketClientMessageHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (Socks5PacketClientMessageHeadroom) FrontHeadroom() int {
	return 3 + socks5.MaxAddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (Socks5PacketClientMessageHeadroom) RearHeadroom() int {
	return 0
}

// Socks5PacketServerMessageHeadroom defines the headroom required by a server message.
//
// Socks5PacketServerMessageHeadroom implements the zerocopy Headroom interface.
type Socks5PacketServerMessageHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (Socks5PacketServerMessageHeadroom) FrontHeadroom() int {
	return 3 + socks5.IPv6AddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (Socks5PacketServerMessageHeadroom) RearHeadroom() int {
	return 0
}

// Socks5PacketClientPacker implements the zerocopy ClientPacker interface.
type Socks5PacketClientPacker struct {
	Socks5PacketClientMessageHeadroom

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

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *Socks5PacketClientPacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
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
	Socks5PacketServerMessageHeadroom

	// serverAddrPort is the SOCKS5 server's IP and port.
	serverAddrPort netip.AddrPort
}

// NewSocks5PacketClientUnpacker creates a SOCKS5 packet client unpacker.
func NewSocks5PacketClientUnpacker(serverAddrPort netip.AddrPort) *Socks5PacketClientUnpacker {
	return &Socks5PacketClientUnpacker{
		serverAddrPort: serverAddrPort,
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
type Socks5PacketServerPacker struct {
	Socks5PacketServerMessageHeadroom
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
	Socks5PacketClientMessageHeadroom

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
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

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

	// preferIPv6 controls whether the direct client prefers IPv6 addresses when resolving domain targets.
	preferIPv6 bool
}

// NewDirectPacketClientPackUnpacker creates a zerocopy.ClientPackUnpacker for direct connection.
func NewDirectPacketClientPackUnpacker(mtu int, preferIPv6 bool) *DirectPacketClientPackUnpacker {
	return &DirectPacketClientPackUnpacker{
		mtu:        mtu,
		preferIPv6: preferIPv6,
	}
}

func (p *DirectPacketClientPackUnpacker) updateDomainIPCache(targetAddr conn.Addr) error {
	if p.cachedDomain != targetAddr.Domain() {
		ip, err := targetAddr.ResolveIP(p.preferIPv6)
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

// ShadowsocksNonePacketHeadroom implements the zerocopy Headroom interface.
type ShadowsocksNonePacketHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (p *ShadowsocksNonePacketHeadroom) FrontHeadroom() int {
	return socks5.MaxAddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (p *ShadowsocksNonePacketHeadroom) RearHeadroom() int {
	return 0
}

// ShadowsocksNonePacketClientPackUnpacker implements the zerocopy ClientPacker and Unpacker interfaces.
type ShadowsocksNonePacketClientPackUnpacker struct {
	ShadowsocksNonePacketHeadroom

	// serverAddrPort is the Shadowsocks none server's IP and port.
	serverAddrPort netip.AddrPort

	// maxPacketSize is the maximum allowed size of a packed packet.
	// The value is calculated from MTU and server address family.
	maxPacketSize int
}

// NewShadowsocksNonePacketClientPackUnpacker creates a zerocopy.ClientPackUnpacker for communicating with a Shadowsocks none server.
func NewShadowsocksNonePacketClientPackUnpacker(serverAddrPort netip.AddrPort, maxPacketSize int) *ShadowsocksNonePacketClientPackUnpacker {
	return &ShadowsocksNonePacketClientPackUnpacker{
		serverAddrPort: serverAddrPort,
		maxPacketSize:  maxPacketSize,
	}
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *ShadowsocksNonePacketClientPackUnpacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
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

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketClientPackUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
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

// ShadowsocksNonePacketServerPackUnpacker implements the zerocopy ServerPacker and Unpacker interfaces.
type ShadowsocksNonePacketServerPackUnpacker struct {
	ShadowsocksNonePacketHeadroom

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (p *ShadowsocksNonePacketServerPackUnpacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	packetStart = payloadStart - targetAddrLen
	packetLen = payloadLen + targetAddrLen
	if packetLen > maxPacketLen {
		err = zerocopy.ErrPayloadTooBig
	}
	socks5.WriteAddrFromAddrPort(b[packetStart:], sourceAddrPort)
	return
}

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketServerPackUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	var targetAddrLen int
	targetAddr, targetAddrLen, p.cachedDomain, err = socks5.ConnAddrFromSliceWithDomainCache(b[packetStart:packetStart+packetLen], p.cachedDomain)
	payloadStart = packetStart + targetAddrLen
	payloadLen = packetLen - targetAddrLen
	return
}

// Socks5PacketHeadroom implements the zerocopy Headroom interface.
type Socks5PacketHeadroom struct{}

// FrontHeadroom implements the zerocopy.Headroom FrontHeadroom method.
func (p *Socks5PacketHeadroom) FrontHeadroom() int {
	return 3 + socks5.MaxAddrLen
}

// RearHeadroom implements the zerocopy.Headroom RearHeadroom method.
func (p *Socks5PacketHeadroom) RearHeadroom() int {
	return 0
}

// Socks5PacketClientPackUnpacker implements the zerocopy ClientPacker and Unpacker interfaces.
type Socks5PacketClientPackUnpacker struct {
	Socks5PacketHeadroom

	// serverAddrPort is the SOCKS5 server's IP and port.
	serverAddrPort netip.AddrPort

	// maxPacketSize is the maximum allowed size of a packed packet.
	// The value is calculated from MTU and server address family.
	maxPacketSize int
}

// NewSocks5PacketClientPackUnpacker creates a zerocopy.ClientPackUnpacker for communicating with a SOCKS5 server.
func NewSocks5PacketClientPackUnpacker(serverAddrPort netip.AddrPort, maxPacketSize int) *Socks5PacketClientPackUnpacker {
	return &Socks5PacketClientPackUnpacker{
		serverAddrPort: serverAddrPort,
		maxPacketSize:  maxPacketSize,
	}
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *Socks5PacketClientPackUnpacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
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

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *Socks5PacketClientPackUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
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

// Socks5PacketServerPackUnpacker implements the zerocopy ServerPacker and Unpacker interfaces.
type Socks5PacketServerPackUnpacker struct {
	Socks5PacketHeadroom

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (p *Socks5PacketServerPackUnpacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
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

// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *Socks5PacketServerPackUnpacker) UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
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

package direct

import (
	"fmt"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

var (
	DefaultDirectClientPacketPackUnpacker    DirectPacketPackUnpacker
	DefaultShadowsocksNonePacketPackUnpacker ShadowsocksNonePacketPackUnpacker
	DefaultSocks5PacketPackUnpacker          Socks5PacketPackUnpacker
)

// DirectPacketPackUnpacker implements the zerocopy Packer and Unpacker interfaces.
type DirectPacketPackUnpacker struct {
	zerocopy.ZeroHeadroom
	targetAddr socks5.Addr
}

// NewDirectClient creates a direct client that passes packets through without doing anything.
func NewDirectClient() *DirectPacketPackUnpacker {
	return &DirectPacketPackUnpacker{}
}

// NewDirectServer creates a direct server that forwards packets to the specified target address.
func NewDirectServer(targetAddr socks5.Addr) *DirectPacketPackUnpacker {
	return &DirectPacketPackUnpacker{
		targetAddr: targetAddr,
	}
}

// PackInPlace implements the Packer PackInPlace method.
func (p *DirectPacketPackUnpacker) PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	packetStart = payloadStart
	packetLen = payloadLen
	return
}

// UnpackInPlace implements the Unpacker UnpackInPlace method.
func (p *DirectPacketPackUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error) {
	targetAddr = p.targetAddr
	hasTargetAddr = targetAddr != nil
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

// ShadowsocksNonePacketPackUnpacker implements the zerocopy Packer and Unpacker interfaces.
type ShadowsocksNonePacketPackUnpacker struct{}

// FrontHeadroom implements the Packer FrontHeadroom method.
func (p *ShadowsocksNonePacketPackUnpacker) FrontHeadroom() int {
	return socks5.MaxAddrLen
}

// RearHeadroom implements the Packer RearHeadroom method.
func (p *ShadowsocksNonePacketPackUnpacker) RearHeadroom() int {
	return 0
}

// PackInPlace implements the Packer PackInPlace method.
func (p *ShadowsocksNonePacketPackUnpacker) PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	packetStart = payloadStart - len(targetAddr)
	packetLen = payloadLen + len(targetAddr)
	copy(b[packetStart:], targetAddr)
	return
}

// UnpackInPlace implements the Unpacker UnpackInPlace method.
func (p *ShadowsocksNonePacketPackUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error) {
	targetAddr, err = socks5.SplitAddr(b[packetStart : packetStart+packetLen])
	hasTargetAddr = true
	payloadStart = packetStart + len(targetAddr)
	payloadLen = packetLen - len(targetAddr)
	return
}

// Socks5PacketPackUnpacker implements the zerocopy Packer and Unpacker interfaces.
type Socks5PacketPackUnpacker struct{}

// FrontHeadroom implements the Packer FrontHeadroom method.
func (p *Socks5PacketPackUnpacker) FrontHeadroom() int {
	return 3 + socks5.MaxAddrLen
}

// RearHeadroom implements the Packer RearHeadroom method.
func (p *Socks5PacketPackUnpacker) RearHeadroom() int {
	return 0
}

// PackInPlace implements the Packer PackInPlace method.
func (p *Socks5PacketPackUnpacker) PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	packetStart = payloadStart - len(targetAddr) - 3
	packetLen = payloadLen + len(targetAddr) + 3
	pkt := b[packetStart : packetStart+packetLen]
	socks5.WritePacketHeader(pkt)
	copy(pkt[3:], targetAddr)
	return
}

// UnpackInPlace implements the Unpacker UnpackInPlace method.
func (p *Socks5PacketPackUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error) {
	if packetLen < 3 {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	pkt := b[packetStart : packetStart+packetLen]
	err = socks5.ValidatePacketHeader(pkt)
	if err != nil {
		return
	}

	targetAddr, err = socks5.SplitAddr(pkt[3:])
	hasTargetAddr = true
	payloadStart = packetStart + len(targetAddr) + 3
	payloadLen = packetLen - len(targetAddr) - 3
	return
}

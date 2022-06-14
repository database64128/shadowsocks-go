package direct

import (
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// DirectPacketPackUnpacker implements the zerocopy Packer and Unpacker interfaces.
type DirectPacketPackUnpacker struct {
	zerocopy.ZeroHeadroom
	targetAddr socks5.Addr
}

func NewDirectClient() *DirectPacketPackUnpacker {
	return &DirectPacketPackUnpacker{}
}

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
func (p *DirectPacketPackUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, payloadStart, payloadLen int, err error) {
	targetAddr = p.targetAddr
	payloadStart = packetStart
	payloadLen = packetLen
	return
}

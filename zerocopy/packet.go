package zerocopy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"

	"github.com/database64128/shadowsocks-go/conn"
)

// Used in packet size calculations.
const (
	IPv4HeaderLength = 20
	IPv6HeaderLength = 40
	UDPHeaderLength  = 8
)

var (
	ErrPacketTooSmall = errors.New("packet too small to unpack")
	ErrPayloadTooBig  = errors.New("payload too big to pack")
)

// MaxPacketSizeForAddr calculates the maximum packet size for the given address
// based on the MTU and the address family.
func MaxPacketSizeForAddr(mtu int, addr netip.Addr) int {
	if addr.Is4() || addr.Is4In6() {
		return mtu - IPv4HeaderLength - UDPHeaderLength
	}
	return mtu - IPv6HeaderLength - UDPHeaderLength
}

// ClientPacker processes raw payload into packets ready to be sent to servers.
type ClientPacker interface {
	Headroom

	// PackInPlace packs the payload in-place into a packet ready for sending and returns
	// the destination address, packet start offset, packet length, or an error if packing fails.
	PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error)
}

// ServerPacker processes raw payload into packets ready to be sent to clients.
type ServerPacker interface {
	Headroom

	// PackInPlace packs the payload in-place into a packet ready for sending and returns
	// packet start offset, packet length, or an error if packing fails.
	PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error)
}

// ClientUnpacker processes packets received from the server into raw payload.
type ClientUnpacker interface {
	Headroom

	// UnpackInPlace unpacks the packet in-place and returns packet source address, payload start offset, payload length, or an error if unpacking fails.
	UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error)
}

// ServerUnpacker processes packets received from the client into raw payload.
type ServerUnpacker interface {
	Headroom

	// UnpackInPlace unpacks the packet in-place and returns target address, payload start offset, payload length, or an error if unpacking fails.
	UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error)
}

// ClientPackUnpacker implements both ClientPacker and ClientUnpacker interfaces.
type ClientPackUnpacker interface {
	ClientPacker
	ClientUnpacker
}

// ServerPackUnpacker implements both ServerPacker and ServerUnpacker interfaces.
type ServerPackUnpacker interface {
	ServerPacker
	ServerUnpacker
}

// ClientServerPackUnpackerTestFunc tests the client pack-unpacker and the server pack-unpacker with the following precedure:
// 1. Client packer packs.
// 2. Server unpacker unpacks.
// 3. Server packer packs.
// 4. Client unpacker unpacks.
func ClientServerPackUnpackerTestFunc(t tester, c ClientPackUnpacker, s ServerPackUnpacker) {
	const packetSize = 1452

	frontHeadroom := c.FrontHeadroom()
	if s.FrontHeadroom() > frontHeadroom {
		frontHeadroom = s.FrontHeadroom()
	}
	rearHeadroom := c.RearHeadroom()
	if s.RearHeadroom() > rearHeadroom {
		rearHeadroom = s.RearHeadroom()
	}
	if frontHeadroom+rearHeadroom >= packetSize {
		t.Fatal("Too much headroom:", frontHeadroom, rearHeadroom)
	}

	b := make([]byte, packetSize)
	payloadStart := frontHeadroom
	payloadLen := packetSize - frontHeadroom - rearHeadroom
	payload := b[payloadStart : payloadStart+payloadLen]
	targetAddrPort := netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	targetAddr := conn.AddrFromIPPort(targetAddrPort)

	// Fill random payload.
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Backup payload.
	payloadBackup := make([]byte, len(payload))
	copy(payloadBackup, payload)

	// Client packs.
	destAddr, pkts, pktl, err := c.PackInPlace(b, targetAddr, payloadStart, payloadLen)
	if err != nil {
		t.Fatal(err)
	}

	// Server unpacks.
	ta, ps, pl, err := s.UnpackInPlace(b, destAddr, pkts, pktl)
	if err != nil {
		t.Fatal(err)
	}

	// Check target address.
	if ta != targetAddr {
		t.Errorf("Target address mismatch: c: %s, s: %s", targetAddr, ta)
	}

	// Check payload.
	p := b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: c: %v, s: %v", payloadBackup, p)
	}

	// Server packs.
	pkts, pktl, err = s.PackInPlace(b, targetAddrPort, ps, pl, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	tap, ps, pl, err := c.UnpackInPlace(b, destAddr, pkts, pktl)
	if err != nil {
		t.Fatal(err)
	}

	// Check target address.
	if tap != targetAddrPort {
		t.Errorf("Target address mismatch: c: %s, s: %s", targetAddrPort, tap)
	}

	// Check payload.
	p = b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: c: %v, s: %v", payloadBackup, p)
	}
}

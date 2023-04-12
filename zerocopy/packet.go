package zerocopy

import (
	"bytes"
	"context"
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

	// Next Header + Hdr Ext Len + Option Type + Opt Data Len + Jumbo Payload Length (u32be)
	JumboPayloadOptionLength = 8
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
	if mtu > 65575 {
		return mtu - IPv6HeaderLength - JumboPayloadOptionLength - UDPHeaderLength
	}
	return mtu - IPv6HeaderLength - UDPHeaderLength
}

// ClientPackerInfo contains information about a client packer.
type ClientPackerInfo struct {
	Headroom Headroom
}

// ClientPacker processes raw payload into packets ready to be sent to servers.
type ClientPacker interface {
	// ClientPackerInfo returns information about the client packer.
	ClientPackerInfo() ClientPackerInfo

	// PackInPlace packs the payload in-place into a packet ready for sending and returns
	// the destination address, packet start offset, packet length, or an error if packing fails.
	PackInPlace(ctx context.Context, b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error)
}

// ServerPackerInfo contains information about a server packer.
type ServerPackerInfo struct {
	Headroom Headroom
}

// ServerPacker processes raw payload into packets ready to be sent to clients.
type ServerPacker interface {
	// ServerPackerInfo returns information about the server packer.
	ServerPackerInfo() ServerPackerInfo

	// PackInPlace packs the payload in-place into a packet ready for sending and returns
	// packet start offset, packet length, or an error if packing fails.
	PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error)
}

// ClientUnpackerInfo contains information about a client unpacker.
type ClientUnpackerInfo struct {
	Headroom Headroom
}

// ClientUnpacker processes packets received from the server into raw payload.
type ClientUnpacker interface {
	// ClientUnpackerInfo returns information about the client unpacker.
	ClientUnpackerInfo() ClientUnpackerInfo

	// UnpackInPlace unpacks the packet in-place and returns packet source address, payload start offset, payload length, or an error if unpacking fails.
	UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error)
}

// ServerUnpackerInfo contains information about a server unpacker.
type ServerUnpackerInfo struct {
	Headroom Headroom
}

// ServerUnpacker processes packets received from the client into raw payload.
type ServerUnpacker interface {
	// ServerUnpackerInfo returns information about the server unpacker.
	ServerUnpackerInfo() ServerUnpackerInfo

	// UnpackInPlace unpacks the packet in-place and returns target address, payload start offset, payload length, or an error if unpacking fails.
	UnpackInPlace(b []byte, sourceAddrPort netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error)

	// NewPacker creates a new server session for the current client session and returns the server session's packer, or an error.
	NewPacker() (ServerPacker, error)
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

// ClientServerPackerUnpackerTestFunc tests the client and server following these steps:
// 1. Client packer packs.
// 2. Server unpacker unpacks.
// 3. Server packer packs.
// 4. Client unpacker unpacks.
func ClientServerPackerUnpackerTestFunc(t tester, clientPacker ClientPacker, clientUnpacker ClientUnpacker, serverPacker ServerPacker, serverUnpacker ServerUnpacker) {
	const (
		packetSize = 1452
		payloadLen = 1280
	)

	headroom := MaxHeadroom(clientPacker.ClientPackerInfo().Headroom, serverPacker.ServerPackerInfo().Headroom)

	b := make([]byte, headroom.Front+payloadLen+headroom.Rear)
	payload := b[headroom.Front : headroom.Front+payloadLen]
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
	destAddr, pkts, pktl, err := clientPacker.PackInPlace(context.Background(), b, targetAddr, headroom.Front, payloadLen)
	if err != nil {
		t.Fatal(err)
	}

	// Server unpacks.
	ta, ps, pl, err := serverUnpacker.UnpackInPlace(b, destAddr, pkts, pktl)
	if err != nil {
		t.Fatal(err)
	}

	// Check target address.
	if !ta.Equals(targetAddr) {
		t.Errorf("Target address mismatch: c: %s, s: %s", targetAddr, ta)
	}

	// Check payload.
	p := b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: c: %v, s: %v", payloadBackup, p)
	}

	// Server packs.
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, ps, pl, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	tap, ps, pl, err := clientUnpacker.UnpackInPlace(b, destAddr, pkts, pktl)
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

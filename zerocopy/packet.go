package zerocopy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/socks5"
)

var ErrPacketTooSmall = errors.New("packet too small")

// Packer processes raw payload into packets.
type Packer interface {
	Headroom

	// PackInPlace packs the payload in-place into a packet and returns packet start offset, packet length,
	// or an error if packing fails.
	PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen int) (packetStart, packetLen int, err error)
}

// Unpacker processes packets into raw payload.
type Unpacker interface {
	// UnpackInPlace unpacks the packet in-place and returns target address, payload start offset, payload length,
	// or an error if unpacking fails.
	//
	// If the packed packet does not contain information about the target address, hasTargetAddr should be false,
	// and the packet's source address should be used instead.
	UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error)
}

// PackerUnpackerTestFunc tests the packer and the unpacker by using the packer to pack a random payload
// and using the unpacker to unpack the packed packet.
func PackerUnpackerTestFunc(t *testing.T, packer Packer, unpacker Unpacker) {
	const packetSize = 1452

	frontHeadroom := packer.FrontHeadroom()
	rearHeadroom := packer.RearHeadroom()
	if frontHeadroom+rearHeadroom >= packetSize {
		t.Fatal("Too much headroom:", frontHeadroom, rearHeadroom)
	}

	b := make([]byte, packetSize)
	payloadStart := frontHeadroom
	payloadLen := packetSize - frontHeadroom - rearHeadroom
	payload := b[payloadStart : payloadStart+payloadLen]
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	// Fill random payload.
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Backup payload.
	payloadBackup := make([]byte, len(payload))
	copy(payloadBackup, payload)

	// Pack.
	pkts, pktl, err := packer.PackInPlace(b, targetAddr, payloadStart, payloadLen)
	if err != nil {
		t.Fatal(err)
	}

	// Unpack.
	ta, hta, ps, pl, err := unpacker.UnpackInPlace(b, pkts, pktl)
	if err != nil {
		t.Fatal(err)
	}

	// Check hasTargetAddr.
	if !hta {
		t.Error("Expected hasTargetAddr to be true")
	}

	// Check target address.
	if !bytes.Equal(targetAddr, ta) {
		t.Errorf("Target address mismatch: c: %s, s: %s", targetAddr, ta)
	}

	// Check payload.
	p := b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: c: %v, s: %v", payloadBackup, p)
	}
}

// PackUnpacker implements both Packer and Unpacker interfaces.
type PackUnpacker interface {
	Packer
	Unpacker
}

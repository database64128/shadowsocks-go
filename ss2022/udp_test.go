package ss2022

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/socks5"
)

func testUDPClientServer(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, clientShouldPad, serverShouldPad func(socks5.Addr) bool) {
	const packetSize = 1452

	c := NewUDPClient(clientCipherConfig, clientShouldPad, clientCipherConfig.ClientPSKHashes())
	s := NewUDPServer(serverCipherConfig, serverShouldPad, serverCipherConfig.ServerPSKHashMap())

	clientPacker, clientUnpacker, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	frontHeadroom := clientPacker.FrontHeadroom() + 8 // Compensate for server message overhead.
	rearHeadroom := clientPacker.RearHeadroom()
	if frontHeadroom+rearHeadroom >= packetSize {
		t.Fatal("Too much headroom:", frontHeadroom, rearHeadroom)
	}

	b := make([]byte, packetSize)
	payloadStart := frontHeadroom
	payloadLen := packetSize - frontHeadroom - rearHeadroom
	payload := b[payloadStart : payloadStart+payloadLen]
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	// Fill random payload.
	_, err = rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Backup payload.
	payloadBackup := make([]byte, len(payload))
	copy(payloadBackup, payload)

	// Client packs.
	pkts, pktl, err := clientPacker.PackInPlace(b, targetAddr, payloadStart, payloadLen)
	if err != nil {
		t.Fatal(err)
	}
	p := b[pkts : pkts+pktl]

	// Server unpacks.
	csid, err := s.SessionInfo(p)
	if err != nil {
		t.Fatal(err)
	}
	serverUnpacker, err := s.NewUnpacker(p, csid)
	if err != nil {
		t.Fatal(err)
	}
	ta, ps, pl, err := serverUnpacker.UnpackInPlace(b, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Check target address.
	if !bytes.Equal(targetAddr, ta) {
		t.Errorf("Target address mismatch: c: %s, s: %s", targetAddr, ta)
	}

	// Check payload.
	p = b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: c: %v, s: %v", payloadBackup, p)
	}

	// Fill random again.
	_, err = rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}
	copy(payloadBackup, payload)

	// Server packs.
	serverPacker, err := s.NewPacker(csid)
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddr, payloadStart, payloadLen)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	ta, ps, pl, err = clientUnpacker.UnpackInPlace(b, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Check target address.
	if !bytes.Equal(targetAddr, ta) {
		t.Errorf("Target address mismatch: s: %s, c: %s", targetAddr, ta)
	}

	// Check payload.
	p = b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: s: %v, c: %v", payloadBackup, p)
	}
}

func TestUDPClientServerNoEIH(t *testing.T) {
	cipherConfig128, err := NewRandomCipherConfig("2022-blake3-aes-128-gcm", 16, 0)
	if err != nil {
		t.Fatal(err)
	}
	cipherConfig256, err := NewRandomCipherConfig("2022-blake3-aes-256-gcm", 32, 0)
	if err != nil {
		t.Fatal(err)
	}

	testUDPClientServer(t, cipherConfig128, cipherConfig128, NoPadding, NoPadding)
	testUDPClientServer(t, cipherConfig128, cipherConfig128, PadPlainDNS, PadPlainDNS)
	testUDPClientServer(t, cipherConfig128, cipherConfig128, PadAll, PadAll)
	testUDPClientServer(t, cipherConfig256, cipherConfig256, NoPadding, NoPadding)
	testUDPClientServer(t, cipherConfig256, cipherConfig256, PadPlainDNS, PadPlainDNS)
	testUDPClientServer(t, cipherConfig256, cipherConfig256, PadAll, PadAll)
}

func TestUDPClientServerWithEIH(t *testing.T) {
	serverCipherConfig128, err := NewRandomCipherConfig("2022-blake3-aes-128-gcm", 16, 7)
	if err != nil {
		t.Fatal(err)
	}
	serverCipherConfig256, err := NewRandomCipherConfig("2022-blake3-aes-256-gcm", 32, 7)
	if err != nil {
		t.Fatal(err)
	}

	clientCipherConfig128 := CipherConfig{
		PSK:  serverCipherConfig128.PSKs[0],
		PSKs: [][]byte{serverCipherConfig128.PSK},
	}
	clientCipherConfig256 := CipherConfig{
		PSK:  serverCipherConfig256.PSKs[0],
		PSKs: [][]byte{serverCipherConfig256.PSK},
	}

	testUDPClientServer(t, &clientCipherConfig128, serverCipherConfig128, NoPadding, NoPadding)
	testUDPClientServer(t, &clientCipherConfig128, serverCipherConfig128, PadPlainDNS, PadPlainDNS)
	testUDPClientServer(t, &clientCipherConfig128, serverCipherConfig128, PadAll, PadAll)
	testUDPClientServer(t, &clientCipherConfig256, serverCipherConfig256, NoPadding, NoPadding)
	testUDPClientServer(t, &clientCipherConfig256, serverCipherConfig256, PadPlainDNS, PadPlainDNS)
	testUDPClientServer(t, &clientCipherConfig256, serverCipherConfig256, PadAll, PadAll)
}

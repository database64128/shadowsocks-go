package ss2022

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
)

const (
	name       = "test"
	mtu        = 1500
	packetSize = 1452
	payloadLen = 1280
	fwmark     = 10240
)

// UDP jumbograms.
const (
	jumboMTU        = 128 * 1024
	jumboPacketSize = 128*1024 - 40 - 8 - 8
	jumboPayloadLen = 127 * 1024
)

var (
	targetAddr           = conn.AddrFromIPPort(targetAddrPort)
	targetAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	serverAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 1080)
	clientAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 10800)
	replayClientAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 10801)
	replayServerAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 10802)
)

func testUDPClientServer(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, clientShouldPad, serverShouldPad PaddingPolicy, mtu, packetSize, payloadLen int) {
	c := NewUDPClient(serverAddrPort, name, mtu, fwmark, clientCipherConfig, clientShouldPad, clientCipherConfig.ClientPSKHashes())
	s := NewUDPServer(serverCipherConfig, serverShouldPad, serverCipherConfig.ServerPSKHashMap())

	fixedName := c.String()
	if fixedName != name {
		t.Errorf("Fixed name mismatch: in: %s, out: %s", name, fixedName)
	}

	fixedMaxPacketSize, fixedFwmark := c.LinkInfo()
	if fixedFwmark != fwmark {
		t.Errorf("Fixed fwmark mismatch: in: %d, out: %d", fwmark, fixedFwmark)
	}
	if fixedMaxPacketSize != packetSize {
		t.Errorf("Fixed MTU mismatch: in: %d, out: %d", mtu, fixedFwmark)
	}

	clientPacker, clientUnpacker, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	frontHeadroom := clientPacker.FrontHeadroom() + 8 // Compensate for server message overhead.
	rearHeadroom := clientPacker.RearHeadroom()
	b := make([]byte, frontHeadroom+payloadLen+rearHeadroom)
	payload := b[frontHeadroom : frontHeadroom+payloadLen]

	// Fill random payload.
	_, err = rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Backup payload.
	payloadBackup := make([]byte, len(payload))
	copy(payloadBackup, payload)

	// Client packs.
	dap, pkts, pktl, err := clientPacker.PackInPlace(b, targetAddr, frontHeadroom, payloadLen)
	if err != nil {
		t.Fatal(err)
	}
	if dap != serverAddrPort {
		t.Errorf("Expected packed client packet destAddrPort %s, got %s", serverAddrPort, dap)
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
	ta, ps, pl, err := serverUnpacker.UnpackInPlace(b, clientAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Check target address.
	if !ta.Equals(targetAddr) {
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
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	tap, ps, pl, err := clientUnpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Check target address.
	if tap != targetAddrPort {
		t.Errorf("Target address mismatch: s: %s, c: %s", targetAddrPort, tap)
	}

	// Check payload.
	p = b[ps : ps+pl]
	if !bytes.Equal(payloadBackup, p) {
		t.Errorf("Payload mismatch: s: %v, c: %v", payloadBackup, p)
	}
}

func testUDPClientServerSessionChangeAndReplay(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig) {
	shouldPad, err := ParsePaddingPolicy("")
	if err != nil {
		t.Fatal(err)
	}

	c := NewUDPClient(serverAddrPort, name, mtu, fwmark, clientCipherConfig, shouldPad, clientCipherConfig.ClientPSKHashes())
	s := NewUDPServer(serverCipherConfig, shouldPad, serverCipherConfig.ServerPSKHashMap())

	clientPacker, clientUnpacker, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	frontHeadroom := clientPacker.FrontHeadroom() + 8 // Compensate for server message overhead.
	rearHeadroom := clientPacker.RearHeadroom()
	b := make([]byte, frontHeadroom+payloadLen+rearHeadroom)

	// Client packs.
	dap, pkts, pktl, err := clientPacker.PackInPlace(b, targetAddr, frontHeadroom, payloadLen)
	if err != nil {
		t.Fatal(err)
	}
	if dap != serverAddrPort {
		t.Errorf("Expected packed client packet destAddrPort %s, got %s", serverAddrPort, dap)
	}
	p := b[pkts : pkts+pktl]

	// Server processes client packet.
	csid, err := s.SessionInfo(p)
	if err != nil {
		t.Fatal(err)
	}
	serverUnpacker, err := s.NewUnpacker(p, csid)
	if err != nil {
		t.Fatal(err)
	}

	// Backup processed client packet.
	pb := make([]byte, pktl)
	copy(pb, p)

	// Server unpacks.
	_, _, _, err = serverUnpacker.UnpackInPlace(b, clientAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Server unpacks the same packet again.
	_, _, _, err = serverUnpacker.UnpackInPlace(pb, replayClientAddrPort, 0, pktl)
	var sprErr *ShadowPacketReplayError
	if !errors.As(err, &sprErr) {
		t.Errorf("Expected ShadowPacketReplayError, got %T", err)
	}
	if sprErr.srcAddr != replayClientAddrPort {
		t.Errorf("Expected ShadowPacketReplayError srcAddr %s, got %s", replayClientAddrPort, sprErr.srcAddr)
	}
	if sprErr.sid != csid {
		t.Errorf("Expected ShadowPacketReplayError sid %d, got %d", csid, sprErr.sid)
	}
	if sprErr.pid != 0 {
		t.Errorf("Expected ShadowPacketReplayError pid 0, got %d", sprErr.pid)
	}

	// Server packs.
	serverPacker, err := s.NewPacker(csid)
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}
	ssid0 := serverPacker.(*ShadowPacketServerPacker).ssid

	// Backup packed server packet.
	pb0 := make([]byte, pktl)
	copy(pb0, b[pkts:pkts+pktl])

	// Client unpacks.
	_, _, _, err = clientUnpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Refresh server session.
	serverPacker, err = s.NewPacker(csid)
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}
	ssid1 := serverPacker.(*ShadowPacketServerPacker).ssid

	// Backup packed server packet.
	pb1 := make([]byte, pktl)
	copy(pb1, b[pkts:pkts+pktl])

	// Trick client into accepting refreshed server session.
	spcu := clientUnpacker.(*ShadowPacketClientUnpacker)
	spcu.oldServerSessionLastSeenTime = spcu.oldServerSessionLastSeenTime.Add(-time.Minute - time.Nanosecond)

	// Client unpacks.
	_, _, _, err = clientUnpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Refresh server session again. No tricks this time!
	serverPacker, err = s.NewPacker(csid)
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	_, _, _, err = clientUnpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != ErrTooManyServerSessions {
		t.Errorf("Expected ErrTooManyServerSessions, got %v", err)
	}

	// Client unpacks pb0.
	_, _, _, err = clientUnpacker.UnpackInPlace(pb0, replayServerAddrPort, 0, len(pb0))
	if !errors.As(err, &sprErr) {
		t.Errorf("Expected ShadowPacketReplayError, got %T", err)
	}
	if sprErr.srcAddr != replayServerAddrPort {
		t.Errorf("Expected ShadowPacketReplayError srcAddr %s, got %s", replayServerAddrPort, sprErr.srcAddr)
	}
	if sprErr.sid != ssid0 {
		t.Errorf("Expected ShadowPacketReplayError sid %d, got %d", ssid0, sprErr.sid)
	}
	if sprErr.pid != 0 {
		t.Errorf("Expected ShadowPacketReplayError pid 0, got %d", sprErr.pid)
	}

	// Client unpacks pb1.
	_, _, _, err = clientUnpacker.UnpackInPlace(pb1, replayServerAddrPort, 0, len(pb1))
	if !errors.As(err, &sprErr) {
		t.Errorf("Expected ShadowPacketReplayError, got %T", err)
	}
	if sprErr.srcAddr != replayServerAddrPort {
		t.Errorf("Expected ShadowPacketReplayError srcAddr %s, got %s", replayServerAddrPort, sprErr.srcAddr)
	}
	if sprErr.sid != ssid1 {
		t.Errorf("Expected ShadowPacketReplayError sid %d, got %d", ssid1, sprErr.sid)
	}
	if sprErr.pid != 0 {
		t.Errorf("Expected ShadowPacketReplayError pid 0, got %d", sprErr.pid)
	}
}

func testUDPClientServerPaddingPolicy(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, mtu, packetSize, payloadLen int) {
	t.Run("NoPadding", func(t *testing.T) {
		testUDPClientServer(t, clientCipherConfig, serverCipherConfig, NoPadding, NoPadding, mtu, packetSize, payloadLen)
	})
	t.Run("PadPlainDNS", func(t *testing.T) {
		testUDPClientServer(t, clientCipherConfig, serverCipherConfig, PadPlainDNS, PadPlainDNS, mtu, packetSize, payloadLen)
	})
	t.Run("PadAll", func(t *testing.T) {
		testUDPClientServer(t, clientCipherConfig, serverCipherConfig, PadAll, PadAll, mtu, packetSize, payloadLen)
	})
}

func testUDPClientServerWithCipher(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig) {
	t.Run("Typical", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, clientCipherConfig, serverCipherConfig, mtu, packetSize, payloadLen)
	})
	t.Run("EmptyPayload", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, clientCipherConfig, serverCipherConfig, mtu, packetSize, 0)
	})
	t.Run("Jumbogram", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, clientCipherConfig, serverCipherConfig, jumboMTU, jumboPacketSize, jumboPayloadLen)
	})
	t.Run("SessionChangeAndReplay", func(t *testing.T) {
		testUDPClientServerSessionChangeAndReplay(t, clientCipherConfig, serverCipherConfig)
	})
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

	t.Run("128", func(t *testing.T) {
		testUDPClientServerWithCipher(t, cipherConfig128, cipherConfig128)
	})
	t.Run("256", func(t *testing.T) {
		testUDPClientServerWithCipher(t, cipherConfig256, cipherConfig256)
	})
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

	t.Run("128", func(t *testing.T) {
		testUDPClientServerWithCipher(t, &clientCipherConfig128, serverCipherConfig128)
	})
	t.Run("256", func(t *testing.T) {
		testUDPClientServerWithCipher(t, &clientCipherConfig256, serverCipherConfig256)
	})
}

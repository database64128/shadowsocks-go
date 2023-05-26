package ss2022

import (
	"bytes"
	"context"
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
	serverAddr           = conn.AddrFromIPPort(serverAddrPort)
	targetAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	serverAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 1080)
	clientAddrPort       = netip.AddrPortFrom(netip.IPv6Unspecified(), 10800)
	replayClientAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 10801)
	replayServerAddrPort = netip.AddrPortFrom(netip.IPv6Unspecified(), 10802)
)

func testUDPClientServer(t *testing.T, ctx context.Context, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, clientShouldPad, serverShouldPad PaddingPolicy, mtu, packetSize, payloadLen int) {
	c := NewUDPClient(serverAddr, name, mtu, conn.DefaultUDPClientListenConfig, DefaultSlidingWindowFilterSize, clientCipherConfig, clientShouldPad)
	s := NewUDPServer(DefaultSlidingWindowFilterSize, userCipherConfig, identityCipherConfig, serverShouldPad)
	s.ReplaceUserLookupMap(userLookupMap)

	clientInfo := c.Info()
	if clientInfo.Name != name {
		t.Errorf("Fixed name mismatch: in: %s, out: %s", name, clientInfo.Name)
	}

	_, clientSession, err := c.NewSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	if clientSession.MaxPacketSize != packetSize {
		t.Errorf("Fixed MTU mismatch: in: %d, out: %d", mtu, clientSession.MaxPacketSize)
	}

	frontHeadroom := clientInfo.PackerHeadroom.Front + 8 // Compensate for server message overhead.
	rearHeadroom := clientInfo.PackerHeadroom.Rear
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
	dap, pkts, pktl, err := clientSession.Packer.PackInPlace(ctx, b, targetAddr, frontHeadroom, payloadLen)
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
	serverUnpacker, _, err := s.NewUnpacker(p, csid)
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
	serverPacker, err := serverUnpacker.NewPacker()
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	tap, ps, pl, err := clientSession.Unpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
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

func testUDPClientServerSessionChangeAndReplay(t *testing.T, ctx context.Context, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap) {
	shouldPad, err := ParsePaddingPolicy("")
	if err != nil {
		t.Fatal(err)
	}

	c := NewUDPClient(serverAddr, name, mtu, conn.DefaultUDPClientListenConfig, DefaultSlidingWindowFilterSize, clientCipherConfig, shouldPad)
	s := NewUDPServer(DefaultSlidingWindowFilterSize, userCipherConfig, identityCipherConfig, shouldPad)
	s.ReplaceUserLookupMap(userLookupMap)

	clientInfo, clientSession, err := c.NewSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	frontHeadroom := clientInfo.PackerHeadroom.Front + 8 // Compensate for server message overhead.
	rearHeadroom := clientInfo.PackerHeadroom.Rear
	b := make([]byte, frontHeadroom+payloadLen+rearHeadroom)

	// Client packs.
	dap, pkts, pktl, err := clientSession.Packer.PackInPlace(ctx, b, targetAddr, frontHeadroom, payloadLen)
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
	serverUnpacker, _, err := s.NewUnpacker(p, csid)
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
	serverPacker, err := serverUnpacker.NewPacker()
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
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Refresh server session.
	serverPacker, err = serverUnpacker.NewPacker()
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
	spcu := clientSession.Unpacker.(*ShadowPacketClientUnpacker)
	spcu.oldServerSessionLastSeenTime = spcu.oldServerSessionLastSeenTime.Add(-time.Minute - time.Nanosecond)

	// Client unpacks.
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != nil {
		t.Error(err)
	}

	// Refresh server session again. No tricks this time!
	serverPacker, err = serverUnpacker.NewPacker()
	if err != nil {
		t.Fatal(err)
	}
	pkts, pktl, err = serverPacker.PackInPlace(b, targetAddrPort, frontHeadroom, payloadLen, packetSize)
	if err != nil {
		t.Fatal(err)
	}

	// Client unpacks.
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(b, serverAddrPort, pkts, pktl)
	if err != ErrTooManyServerSessions {
		t.Errorf("Expected ErrTooManyServerSessions, got %v", err)
	}

	// Client unpacks pb0.
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(pb0, replayServerAddrPort, 0, len(pb0))
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
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(pb1, replayServerAddrPort, 0, len(pb1))
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

func testUDPClientServerPaddingPolicy(t *testing.T, ctx context.Context, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, mtu, packetSize, payloadLen int) {
	t.Run("NoPadding", func(t *testing.T) {
		testUDPClientServer(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, NoPadding, NoPadding, mtu, packetSize, payloadLen)
	})
	t.Run("PadPlainDNS", func(t *testing.T) {
		testUDPClientServer(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, PadPlainDNS, PadPlainDNS, mtu, packetSize, payloadLen)
	})
	t.Run("PadAll", func(t *testing.T) {
		testUDPClientServer(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, PadAll, PadAll, mtu, packetSize, payloadLen)
	})
}

func testUDPClientServerWithCipher(t *testing.T, ctx context.Context, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap) {
	t.Run("Typical", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, mtu, packetSize, payloadLen)
	})
	t.Run("EmptyPayload", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, mtu, packetSize, 0)
	})
	t.Run("Jumbogram", func(t *testing.T) {
		testUDPClientServerPaddingPolicy(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, jumboMTU, jumboPacketSize, jumboPayloadLen)
	})
	t.Run("SessionChangeAndReplay", func(t *testing.T) {
		testUDPClientServerSessionChangeAndReplay(t, ctx, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap)
	})
}

func TestUDPClientServerNoEIH(t *testing.T) {
	ctx := context.Background()
	clientCipherConfig128, userCipherConfig128, err := newRandomCipherConfigTupleNoEIH("2022-blake3-aes-128-gcm", true)
	if err != nil {
		t.Fatal(err)
	}
	clientCipherConfig256, userCipherConfig256, err := newRandomCipherConfigTupleNoEIH("2022-blake3-aes-256-gcm", true)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("128", func(t *testing.T) {
		testUDPClientServerWithCipher(t, ctx, clientCipherConfig128, userCipherConfig128, ServerIdentityCipherConfig{}, nil)
	})
	t.Run("256", func(t *testing.T) {
		testUDPClientServerWithCipher(t, ctx, clientCipherConfig256, userCipherConfig256, ServerIdentityCipherConfig{}, nil)
	})
}

func TestUDPClientServerWithEIH(t *testing.T) {
	ctx := context.Background()
	clientCipherConfig128, identityCipherConfig128, userLookupMap128, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-128-gcm", true)
	if err != nil {
		t.Fatal(err)
	}
	clientCipherConfig256, identityCipherConfig256, userLookupMap256, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-256-gcm", true)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("128", func(t *testing.T) {
		testUDPClientServerWithCipher(t, ctx, clientCipherConfig128, UserCipherConfig{}, identityCipherConfig128, userLookupMap128)
	})
	t.Run("256", func(t *testing.T) {
		testUDPClientServerWithCipher(t, ctx, clientCipherConfig256, UserCipherConfig{}, identityCipherConfig256, userLookupMap256)
	})
}

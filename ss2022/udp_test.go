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

func testUDPClientServer(
	t *testing.T,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	expectedUsername string,
	clientShouldPad, serverShouldPad PaddingPolicy,
	mtu, packetSize, payloadLen int,
) {
	c := NewUDPClient(name, "ip", serverAddr, mtu, conn.DefaultUDPClientListenConfig, DefaultSlidingWindowFilterSize, clientCipherConfig, clientShouldPad)
	s := NewUDPServer(DefaultSlidingWindowFilterSize, userCipherConfig, identityCipherConfig, serverShouldPad)
	s.ReplaceUserLookupMap(userLookupMap)
	ctx := t.Context()

	clientInfo, clientSession, err := c.NewSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	if clientInfo.Name != name {
		t.Errorf("Fixed name mismatch: in: %s, out: %s", name, clientInfo.Name)
	}
	if clientSession.MaxPacketSize != packetSize {
		t.Errorf("Fixed MTU mismatch: in: %d, out: %d", mtu, clientSession.MaxPacketSize)
	}

	frontHeadroom := clientInfo.PackerHeadroom.Front + 8 // Compensate for server message overhead.
	rearHeadroom := clientInfo.PackerHeadroom.Rear
	b := make([]byte, frontHeadroom+payloadLen+rearHeadroom)
	payload := b[frontHeadroom : frontHeadroom+payloadLen]

	// Fill random payload.
	rand.Read(payload)

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
	serverUnpacker, username, err := s.NewUnpacker(p, csid)
	if err != nil {
		t.Fatal(err)
	}
	if username != expectedUsername {
		t.Errorf("username = %q, want %q", username, expectedUsername)
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
	rand.Read(payload)
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

func testUDPClientServerSessionChangeAndReplay(
	t *testing.T,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	expectedUsername string,
	clientShouldPad, serverShouldPad PaddingPolicy,
	mtu, packetSize, payloadLen int,
) {
	c := NewUDPClient(name, "ip", serverAddr, mtu, conn.DefaultUDPClientListenConfig, DefaultSlidingWindowFilterSize, clientCipherConfig, clientShouldPad)
	s := NewUDPServer(DefaultSlidingWindowFilterSize, userCipherConfig, identityCipherConfig, serverShouldPad)
	s.ReplaceUserLookupMap(userLookupMap)
	ctx := t.Context()

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
	serverUnpacker, username, err := s.NewUnpacker(p, csid)
	if err != nil {
		t.Fatal(err)
	}
	if username != expectedUsername {
		t.Errorf("username = %q, want %q", username, expectedUsername)
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
		t.Fatalf("err = %v, want %T", err, sprErr)
	}
	if sprErr.srcAddr != replayClientAddrPort {
		t.Errorf("sprErr.srcAddr = %q, want %q", sprErr.srcAddr, replayClientAddrPort)
	}
	if sprErr.sid != csid {
		t.Errorf("sprErr.sid = %d, want %d", sprErr.sid, csid)
	}
	if sprErr.pid != 0 {
		t.Errorf("sprErr.pid = %d, want 0", sprErr.pid)
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
		t.Fatalf("err = %v, want %T", err, sprErr)
	}
	if sprErr.srcAddr != replayServerAddrPort {
		t.Errorf("sprErr.srcAddr = %q, want %q", sprErr.srcAddr, replayServerAddrPort)
	}
	if sprErr.sid != ssid0 {
		t.Errorf("sprErr.sid = %d, want %d", sprErr.sid, ssid0)
	}
	if sprErr.pid != 0 {
		t.Errorf("sprErr.pid = %d, want 0", sprErr.pid)
	}

	// Client unpacks pb1.
	_, _, _, err = clientSession.Unpacker.UnpackInPlace(pb1, replayServerAddrPort, 0, len(pb1))
	if !errors.As(err, &sprErr) {
		t.Fatalf("err = %v, want %T", err, sprErr)
	}
	if sprErr.srcAddr != replayServerAddrPort {
		t.Errorf("sprErr.srcAddr = %q, want %q", sprErr.srcAddr, replayServerAddrPort)
	}
	if sprErr.sid != ssid1 {
		t.Errorf("sprErr.sid = %d, want %d", sprErr.sid, ssid1)
	}
	if sprErr.pid != 0 {
		t.Errorf("sprErr.pid = %d, want 0", sprErr.pid)
	}
}

var paddingCases = [...]struct {
	name      string
	shouldPad PaddingPolicy
}{
	{"NoPadding", NoPadding},
	{"PadPlainDNS", PadPlainDNS},
	{"PadAll", PadAll},
}

func TestUDPClientServer(t *testing.T) {
	t.Parallel()
	for _, method := range methodCases {
		for _, cipher := range cipherCases {
			t.Run(method, func(t *testing.T) {
				t.Parallel()

				clientCipherConfig,
					userCipherConfig,
					identityCipherConfig,
					userLookupMap,
					username,
					err := cipher.newCipherConfig(method, true)
				if err != nil {
					t.Fatal(err)
				}

				for _, clientShouldPadCase := range paddingCases {
					t.Run(clientShouldPadCase.name, func(t *testing.T) {
						t.Parallel()
						for _, serverShouldPadCase := range paddingCases {
							t.Run(serverShouldPadCase.name, func(t *testing.T) {
								t.Parallel()
								for _, sizeCases := range [...]struct {
									name       string
									mtu        int
									packetSize int
									payloadLen int
								}{
									{"Typical", mtu, packetSize, payloadLen},
									{"EmptyPayload", mtu, packetSize, 0},
									{"Jumbogram", jumboMTU, jumboPacketSize, jumboPayloadLen},
								} {
									t.Run(sizeCases.name, func(t *testing.T) {
										t.Parallel()
										t.Run("RoundTrip", func(t *testing.T) {
											t.Parallel()
											testUDPClientServer(
												t,
												clientCipherConfig,
												userCipherConfig,
												identityCipherConfig,
												userLookupMap,
												username,
												clientShouldPadCase.shouldPad,
												serverShouldPadCase.shouldPad,
												sizeCases.mtu,
												sizeCases.packetSize,
												sizeCases.payloadLen,
											)
										})
										t.Run("SessionChangeAndReplay", func(t *testing.T) {
											t.Parallel()
											testUDPClientServerSessionChangeAndReplay(
												t,
												clientCipherConfig,
												userCipherConfig,
												identityCipherConfig,
												userLookupMap,
												username,
												clientShouldPadCase.shouldPad,
												serverShouldPadCase.shouldPad,
												sizeCases.mtu,
												sizeCases.packetSize,
												sizeCases.payloadLen,
											)
										})
									})
								}
							})
						}
					})
				}
			})
		}
	}
}

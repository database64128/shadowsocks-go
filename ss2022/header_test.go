package ss2022

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	mrand "math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
)

func TestHeaderErrorString(t *testing.T) {
	const errMsg = "time diff is over 30 seconds: expected 1, got 2"
	err := HeaderError[int]{ErrBadTimestamp, 1, 2}
	if err.Error() != errMsg {
		t.FailNow()
	}
}

func TestWriteAndParseTCPRequestFixedLengthHeader(t *testing.T) {
	b := make([]byte, TCPRequestFixedLengthHeaderLength)
	length := mrand.Intn(math.MaxUint16)

	// 1. Good header
	WriteTCPRequestFixedLengthHeader(b, uint16(length))

	n, err := ParseTCPRequestFixedLengthHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != length {
		t.Fatalf("Expected: %d\nGot: %d", length, n)
	}

	// 2. Bad timestamp (31s ago)
	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, err = ParseTCPRequestFixedLengthHeader(b)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 3. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, err = ParseTCPRequestFixedLengthHeader(b)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 4. Bad type
	b[0] = HeaderTypeServerStream

	_, err = ParseTCPRequestFixedLengthHeader(b)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

func TestWriteAndParseTCPRequestVariableLengthHeader(t *testing.T) {
	payloadLen := 1 + mrand.Intn(1024)
	payload := make([]byte, payloadLen)
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}
	targetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 443))
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	noPayloadLen := targetAddrLen + 2 + 1 + mrand.Intn(MaxPaddingLength)
	noPaddingLen := targetAddrLen + 2 + payloadLen
	bufLen := noPaddingLen + MaxPaddingLength
	b := make([]byte, bufLen)

	// 1. Good header (padding + initial payload)
	WriteTCPRequestVariableLengthHeader(b, targetAddr, payload)

	ta, p, err := ParseTCPRequestVariableLengthHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if ta != targetAddr {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (initial payload)
	b = b[:noPaddingLen]
	WriteTCPRequestVariableLengthHeader(b, targetAddr, payload)

	ta, p, err = ParseTCPRequestVariableLengthHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if ta != targetAddr {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Good header (padding)
	b = b[:noPayloadLen]
	WriteTCPRequestVariableLengthHeader(b, targetAddr, nil)

	ta, p, err = ParseTCPRequestVariableLengthHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 0 {
		t.Fatalf("Expected empty initial payload, got length %d", len(p))
	}
	if ta != targetAddr {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 4. Bad header (incomplete padding)
	b = b[:noPayloadLen-1]

	_, _, err = ParseTCPRequestVariableLengthHeader(b)
	if !errors.Is(err, ErrPaddingExceedChunkBorder) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingExceedChunkBorder, err)
	}

	// 5. Bad header (incomplete padding length)
	b = b[:targetAddrLen+1]

	_, _, err = ParseTCPRequestVariableLengthHeader(b)
	if !errors.Is(err, ErrIncompleteHeaderInFirstChunk) {
		t.Fatalf("Expected: %s\nGot: %s", ErrIncompleteHeaderInFirstChunk, err)
	}

	// 6. Bad header (incomplete SOCKS address)
	b = b[:targetAddrLen-1]

	_, _, err = ParseTCPRequestVariableLengthHeader(b)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

func TestWriteAndParseTCPResponseHeader(t *testing.T) {
	const (
		saltLen = 32
		bufLen  = 1 + 8 + saltLen + 2
	)

	b := make([]byte, bufLen)
	length := mrand.Intn(math.MaxUint16)
	requestSalt := make([]byte, saltLen)
	_, err := rand.Read(requestSalt)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header
	WriteTCPResponseHeader(b, requestSalt, uint16(length))

	n, err := ParseTCPResponseHeader(b, requestSalt)
	if err != nil {
		t.Fatal(err)
	}
	if n != length {
		t.Fatalf("Expected: %d\nGot: %d", length, n)
	}

	// 2. Bad request salt
	_, err = rand.Read(b[1+8 : 1+8+saltLen])
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseTCPResponseHeader(b, requestSalt)
	if !errors.Is(err, ErrClientSaltMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrClientSaltMismatch, err)
	}

	// 3. Bad timestamp (31s ago)
	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, err = ParseTCPResponseHeader(b, requestSalt)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 4. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, err = ParseTCPResponseHeader(b, requestSalt)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 5. Bad type
	b[0] = HeaderTypeClientStream

	_, err = ParseTCPResponseHeader(b, requestSalt)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

func TestWriteAndParseSessionIDAndPacketID(t *testing.T) {
	sid := mrand.Uint64()
	pid := mrand.Uint64()
	b := make([]byte, 16)

	WriteSessionIDAndPacketID(b, sid, pid)
	psid, ppid := ParseSessionIDAndPacketID(b)
	if psid != sid {
		t.Fatalf("Expected session ID %d, got %d", sid, psid)
	}
	if ppid != pid {
		t.Fatalf("Expected packet ID %d, got %d", pid, ppid)
	}
}

func TestWriteAndParseUDPClientMessageHeader(t *testing.T) {
	var cachedDomain string
	targetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	noPaddingLen := UDPClientMessageHeaderFixedLength + targetAddrLen
	paddingLen := 1 + mrand.Intn(MaxPaddingLength)
	headerLen := noPaddingLen + paddingLen
	payloadLen := 1 + mrand.Intn(math.MaxUint16)
	bufLen := headerLen + payloadLen
	b := make([]byte, bufLen)
	bNoPadding := b[headerLen-noPaddingLen:]
	headerBuf := b[:headerLen]
	headerNoPaddingBuf := bNoPadding[:headerLen]
	payload := b[headerLen:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	WriteUDPClientMessageHeader(headerNoPaddingBuf, 0, targetAddr)

	ta, cachedDomain, ps, pl, err := ParseUDPClientMessageHeader(bNoPadding, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	ps += headerLen - noPaddingLen
	if ps != headerLen {
		t.Errorf("Expected payload start %d, got %d", headerLen, ps)
	}
	if pl != payloadLen {
		t.Errorf("Expected payload length %d, got %d", payloadLen, pl)
	}
	if ta != targetAddr {
		t.Errorf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (padding)
	WriteUDPClientMessageHeader(headerBuf, paddingLen, targetAddr)

	ta, cachedDomain, ps, pl, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	if ps != headerLen {
		t.Errorf("Expected payload start %d, got %d", headerLen, ps)
	}
	if pl != payloadLen {
		t.Errorf("Expected payload length %d, got %d", payloadLen, pl)
	}
	if ta != targetAddr {
		t.Errorf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Bad header (incomplete SOCKS address)
	b = b[:headerLen-1]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// 4. Bad header (incomplete padding)
	b = b[:len(b)-targetAddrLen]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Errorf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 5. Bad header (incomplete padding length)
	b = b[:1+8+1]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Errorf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 6. Bad timestamp (31s ago)
	b = b[:UDPClientMessageHeaderFixedLength]

	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Errorf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 7. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Errorf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 8. Bad type
	b[0] = HeaderTypeServerPacket

	_, _, _, _, err = ParseUDPClientMessageHeader(b, cachedDomain)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

func TestWriteAndParseUDPServerMessageHeader(t *testing.T) {
	csid := mrand.Uint64()
	sourceAddrPort := netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	sourceAddrPortLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	noPaddingLen := UDPServerMessageHeaderFixedLength + sourceAddrPortLen
	paddingLen := 1 + mrand.Intn(MaxPaddingLength)
	headerLen := noPaddingLen + paddingLen
	payloadLen := 1 + mrand.Intn(math.MaxUint16)
	bufLen := headerLen + payloadLen
	b := make([]byte, bufLen)
	bNoPadding := b[headerLen-noPaddingLen:]
	headerBuf := b[:headerLen]
	headerNoPaddingBuf := bNoPadding[:headerLen]
	payload := b[headerLen:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	WriteUDPServerMessageHeader(headerNoPaddingBuf, csid, 0, sourceAddrPort)

	sa, ps, pl, err := ParseUDPServerMessageHeader(bNoPadding, csid)
	if err != nil {
		t.Fatal(err)
	}
	ps += headerLen - noPaddingLen
	if ps != headerLen {
		t.Errorf("Expected payload start %d, got %d", headerLen, ps)
	}
	if pl != payloadLen {
		t.Errorf("Expected payload length %d, got %d", payloadLen, pl)
	}
	if sa != sourceAddrPort {
		t.Errorf("Expected target address %s, got %s", sourceAddrPort, sa)
	}

	// 2. Good header (pad)
	WriteUDPServerMessageHeader(headerBuf, csid, paddingLen, sourceAddrPort)

	sa, ps, pl, err = ParseUDPServerMessageHeader(b, csid)
	if err != nil {
		t.Fatal(err)
	}
	if ps != headerLen {
		t.Errorf("Expected payload start %d, got %d", headerLen, ps)
	}
	if pl != payloadLen {
		t.Errorf("Expected payload length %d, got %d", payloadLen, pl)
	}
	if sa != sourceAddrPort {
		t.Errorf("Expected target address %s, got %s", sourceAddrPort, sa)
	}

	// 3. Bad header (incomplete SOCKS address)
	b = b[:headerLen-1]

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// 4. Bad header (incomplete padding)
	b = b[:len(b)-sourceAddrPortLen]

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Errorf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 5. Bad header (incomplete padding length)
	b = b[:1+8+8+1]

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Errorf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 6. Bad client session ID
	b = b[:UDPServerMessageHeaderFixedLength]
	badCsid := csid + 1
	binary.BigEndian.PutUint64(b[1+8:], badCsid)

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrClientSessionIDMismatch) {
		t.Errorf("Expected: %s\nGot: %s", ErrClientSessionIDMismatch, err)
	}

	// 7. Bad timestamp (31s ago)
	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Errorf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 8. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(b[1:], uint64(ts.Unix()))

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Errorf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 9. Bad type
	b[0] = HeaderTypeClientPacket

	_, _, _, err = ParseUDPServerMessageHeader(b, csid)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Errorf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

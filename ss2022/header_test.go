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

	// 5. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(b[targetAddrLen:], MaxPaddingLength+1)

	_, _, err = ParseTCPRequestVariableLengthHeader(b)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 6. Bad header (incomplete padding length)
	b = b[:targetAddrLen+1]

	_, _, err = ParseTCPRequestVariableLengthHeader(b)
	if !errors.Is(err, ErrIncompleteHeaderInFirstChunk) {
		t.Fatalf("Expected: %s\nGot: %s", ErrIncompleteHeaderInFirstChunk, err)
	}

	// 7. Bad header (incomplete SOCKS address)
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
	targetAddrHttps := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 443))
	targetAddrHttpsLen := socks5.LengthOfAddrFromConnAddr(targetAddrHttps)
	targetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	payloadLen := mrand.Intn(1024)
	expectedHeaderWithoutPaddingLength := UDPClientMessageHeaderFixedLength + targetAddrLen
	bufLen := UDPClientMessageHeaderMaxLength + payloadLen
	b := make([]byte, bufLen)
	headerBuf := b[:UDPClientMessageHeaderMaxLength]
	payload := b[UDPClientMessageHeaderMaxLength:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	n, err := WriteUDPClientMessageHeader(headerBuf, targetAddr, NoPadding)
	if err != nil {
		t.Fatal(err)
	}
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header := b[UDPClientMessageHeaderMaxLength-n:]

	ta, cachedDomain, ps, pl, err := ParseUDPClientMessageHeader(header, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	p := header[ps : ps+pl]
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if ta != targetAddr {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (pad plain DNS)
	n, err = WriteUDPClientMessageHeader(headerBuf, targetAddrHttps, PadPlainDNS)
	if err != nil {
		t.Fatal(err)
	}
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	n, err = WriteUDPClientMessageHeader(headerBuf, targetAddr, PadPlainDNS)
	if err != nil {
		t.Fatal(err)
	}
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPClientMessageHeaderMaxLength-n:]

	ta, cachedDomain, ps, pl, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	p = header[ps : ps+pl]
	if !bytes.Equal(header[ps:ps+pl], payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if ta != targetAddr {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Good header (pad all)
	n, err = WriteUDPClientMessageHeader(headerBuf, targetAddrHttps, PadAll)
	if err != nil {
		t.Fatal(err)
	}
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPClientMessageHeaderMaxLength-n:]

	ta, cachedDomain, ps, pl, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if err != nil {
		t.Fatal(err)
	}
	p = header[ps : ps+pl]
	if !bytes.Equal(header[ps:ps+pl], payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if ta != targetAddrHttps {
		t.Fatalf("Expected target address %s, got %s", targetAddrHttps, ta)
	}

	// 4. Bad header (missing payload)
	header = header[:len(header)-payloadLen]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrPacketMissingPayload) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketMissingPayload, err)
	}

	// 5. Bad header (incomplete SOCKS address)
	header = header[:len(header)-1]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// 6. Bad header (incomplete padding)
	header = header[:len(header)-targetAddrHttpsLen]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 7. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(header[1+8:], MaxPaddingLength+1)

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 8. Bad header (incomplete padding length)
	header = header[:1+8+1]

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 9. Bad timestamp (31s ago)
	header = header[:UDPClientMessageHeaderFixedLength]

	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 10. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, cachedDomain, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 11. Bad type
	header[0] = HeaderTypeServerPacket

	_, _, _, _, err = ParseUDPClientMessageHeader(header, cachedDomain)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

func TestWriteAndParseUDPServerMessageHeader(t *testing.T) {
	csid := mrand.Uint64()
	sourceAddrPortHttps := netip.AddrPortFrom(netip.IPv6Unspecified(), 443)
	sourceAddrPortHttpsLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPortHttps)
	sourceAddrPort := netip.AddrPortFrom(netip.IPv6Unspecified(), 53)
	sourceAddrPortLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	payloadLen := mrand.Intn(1024)
	expectedHeaderWithoutPaddingLength := UDPServerMessageHeaderFixedLength + sourceAddrPortLen
	bufLen := UDPServerMessageHeaderMaxLength + payloadLen
	b := make([]byte, bufLen)
	headerBuf := b[:UDPServerMessageHeaderMaxLength]
	payload := b[UDPServerMessageHeaderMaxLength:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	n, err := WriteUDPServerMessageHeader(headerBuf, csid, sourceAddrPort, NoPadding)
	if err != nil {
		t.Fatal(err)
	}
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header := b[UDPServerMessageHeaderMaxLength-n:]

	sa, ps, pl, err := ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	p := header[ps : ps+pl]
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if sa != sourceAddrPort {
		t.Fatalf("Expected target address %s, got %s", sourceAddrPort, sa)
	}

	// 2. Good header (pad plain DNS)
	n, err = WriteUDPServerMessageHeader(headerBuf, csid, sourceAddrPortHttps, PadPlainDNS)
	if err != nil {
		t.Fatal(err)
	}
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	n, err = WriteUDPServerMessageHeader(headerBuf, csid, sourceAddrPort, PadPlainDNS)
	if err != nil {
		t.Fatal(err)
	}
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPServerMessageHeaderMaxLength-n:]

	sa, ps, pl, err = ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	p = header[ps : ps+pl]
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if sa != sourceAddrPort {
		t.Fatalf("Expected target address %s, got %s", sourceAddrPort, sa)
	}

	// 3. Good header (pad all)
	n, err = WriteUDPServerMessageHeader(headerBuf, csid, sourceAddrPortHttps, PadAll)
	if err != nil {
		t.Fatal(err)
	}
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPServerMessageHeaderMaxLength-n:]

	sa, ps, pl, err = ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	p = header[ps : ps+pl]
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if sa != sourceAddrPortHttps {
		t.Fatalf("Expected target address %s, got %s", sourceAddrPortHttps, sa)
	}

	// 4. Bad header (missing payload)
	header = header[:len(header)-payloadLen]

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketMissingPayload) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketMissingPayload, err)
	}

	// 5. Bad header (incomplete SOCKS address)
	header = header[:len(header)-1]

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// 6. Bad header (incomplete padding)
	header = header[:len(header)-sourceAddrPortHttpsLen]

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 7. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(header[1+8+8:], MaxPaddingLength+1)

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 8. Bad header (incomplete padding length)
	header = header[:1+8+8+1]

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 9. Bad client session ID
	header = header[:UDPServerMessageHeaderFixedLength]
	badCsid := csid + 1
	binary.BigEndian.PutUint64(header[1+8:], badCsid)

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrClientSessionIDMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrClientSessionIDMismatch, err)
	}

	// 10. Bad timestamp (31s ago)
	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 11. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 12. Bad type
	header[0] = HeaderTypeClientPacket

	_, _, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

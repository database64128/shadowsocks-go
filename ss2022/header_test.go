package ss2022

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	mrand "math/rand"
	"net/netip"
	"testing"
	"time"

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
	payloadLen := mrand.Intn(1024)
	payload := make([]byte, payloadLen)
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 443))
	expectedHeaderWithPayloadLength := len(targetAddr) + 2 + payloadLen
	bufLen := TCPRequestVariableLengthHeaderNoPayloadMaxLength + payloadLen
	b := make([]byte, bufLen)

	// 1. Good header (with initial payload)
	n := WriteTCPRequestVariableLengthHeader(b, targetAddr, payload)
	if n != expectedHeaderWithPayloadLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithPayloadLength, n)
	}
	header := b[:n]

	ta, p, err := ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (no payload)
	n = WriteTCPRequestVariableLengthHeader(b, targetAddr, nil)
	if n <= len(targetAddr)+2 {
		t.Fatalf("Header should have been padded!\nActual length: %d", n)
	}
	header = b[:n]

	ta, p, err = ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 0 {
		t.Fatalf("Expected empty initial payload, got length %d", len(p))
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Good header (padding + payload)
	n += copy(b[n:], payload)
	header = b[:n]

	ta, p, err = ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 4. Bad header (incomplete padding)
	n -= payloadLen
	n -= 1
	header = b[:n]

	_, _, err = ParseTCPRequestVariableLengthHeader(header)
	if !errors.Is(err, ErrPaddingExceedChunkBorder) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingExceedChunkBorder, err)
	}

	// 5. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(b[len(targetAddr):], MaxPaddingLength+1)

	_, _, err = ParseTCPRequestVariableLengthHeader(header)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 6. Bad header (incomplete padding length)
	n = len(targetAddr) + 1
	header = b[:n]

	_, _, err = ParseTCPRequestVariableLengthHeader(header)
	if !errors.Is(err, ErrIncompleteHeaderInFirstChunk) {
		t.Fatalf("Expected: %s\nGot: %s", ErrIncompleteHeaderInFirstChunk, err)
	}

	// 7. Bad header (incomplete SOCKS address)
	n = len(targetAddr) - 1
	header = b[:n]

	_, _, err = ParseTCPRequestVariableLengthHeader(header)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Expected: %s\nGot: %s", io.ErrShortBuffer, err)
	}
}

func TestWriteAndParseTCPResponseHeader(t *testing.T) {
	b := make([]byte, TCPResponseHeaderMaxLength)
	length := mrand.Intn(math.MaxUint16)
	requestSalt := make([]byte, 32)
	_, err := rand.Read(requestSalt)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header
	n := WriteTCPResponseHeader(b, requestSalt, uint16(length))
	if n != TCPResponseHeaderMaxLength {
		t.Fatalf("Expected: %d\nGot: %d", TCPResponseHeaderMaxLength, n)
	}

	n, err = ParseTCPResponseHeader(b, requestSalt)
	if err != nil {
		t.Fatal(err)
	}
	if n != length {
		t.Fatalf("Expected: %d\nGot: %d", length, n)
	}

	// 2. Bad request salt
	_, err = rand.Read(b[1+8 : 1+8+32])
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
	targetAddrHttps := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 443))
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	payloadLen := mrand.Intn(1024)
	expectedHeaderWithoutPaddingLength := UDPClientMessageHeaderFixedLength + len(targetAddr)
	bufLen := UDPClientMessageHeaderMaxLength + payloadLen
	b := make([]byte, bufLen)
	headerBuf := b[:UDPClientMessageHeaderMaxLength]
	payload := b[UDPClientMessageHeaderMaxLength:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	n := WriteUDPClientMessageHeader(headerBuf, targetAddr, NoPadding)
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header := b[UDPClientMessageHeaderMaxLength-n:]

	ta, p, err := ParseUDPClientMessageHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (pad plain DNS)
	n = WriteUDPClientMessageHeader(headerBuf, targetAddrHttps, PadPlainDNS)
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	n = WriteUDPClientMessageHeader(headerBuf, targetAddr, PadPlainDNS)
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPClientMessageHeaderMaxLength-n:]

	ta, p, err = ParseUDPClientMessageHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Good header (pad all)
	n = WriteUDPClientMessageHeader(headerBuf, targetAddrHttps, PadAll)
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPClientMessageHeaderMaxLength-n:]

	ta, p, err = ParseUDPClientMessageHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddrHttps) {
		t.Fatalf("Expected target address %s, got %s", targetAddrHttps, ta)
	}

	// 4. Bad header (missing payload)
	header = header[:len(header)-payloadLen]

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrPacketMissingPayload) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketMissingPayload, err)
	}

	// 5. Bad header (incomplete SOCKS address)
	header = header[:len(header)-1]

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Expected: %s\nGot: %s", io.ErrShortBuffer, err)
	}

	// 6. Bad header (incomplete padding)
	header = header[:len(header)-len(targetAddrHttps)]

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 7. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(header[1+8:], MaxPaddingLength+1)

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 8. Bad header (incomplete padding length)
	header = header[:1+8+1]

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 9. Bad timestamp (31s ago)
	header = header[:UDPClientMessageHeaderFixedLength]

	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 10. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 11. Bad type
	header[0] = HeaderTypeServerPacket

	_, _, err = ParseUDPClientMessageHeader(header)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

func TestWriteAndParseUDPServerMessageHeader(t *testing.T) {
	csid := mrand.Uint64()
	targetAddrHttps := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 443))
	targetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	payloadLen := mrand.Intn(1024)
	expectedHeaderWithoutPaddingLength := UDPServerMessageHeaderFixedLength + len(targetAddr)
	bufLen := UDPServerMessageHeaderMaxLength + payloadLen
	b := make([]byte, bufLen)
	headerBuf := b[:UDPServerMessageHeaderMaxLength]
	payload := b[UDPServerMessageHeaderMaxLength:]
	_, err := rand.Read(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Good header (no padding)
	n := WriteUDPServerMessageHeader(headerBuf, csid, targetAddr, NoPadding)
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header := b[UDPServerMessageHeaderMaxLength-n:]

	ta, p, err := ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 2. Good header (pad plain DNS)
	n = WriteUDPServerMessageHeader(headerBuf, csid, targetAddrHttps, PadPlainDNS)
	if n != expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected n %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	n = WriteUDPServerMessageHeader(headerBuf, csid, targetAddr, PadPlainDNS)
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPServerMessageHeaderMaxLength-n:]

	ta, p, err = ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddr) {
		t.Fatalf("Expected target address %s, got %s", targetAddr, ta)
	}

	// 3. Good header (pad all)
	n = WriteUDPServerMessageHeader(headerBuf, csid, targetAddrHttps, PadAll)
	if n <= expectedHeaderWithoutPaddingLength {
		t.Fatalf("Expected padded header length greater than %d, got %d", expectedHeaderWithoutPaddingLength, n)
	}
	header = b[UDPServerMessageHeaderMaxLength-n:]

	ta, p, err = ParseUDPServerMessageHeader(header, csid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if !bytes.Equal(ta, targetAddrHttps) {
		t.Fatalf("Expected target address %s, got %s", targetAddrHttps, ta)
	}

	// 4. Bad header (missing payload)
	header = header[:len(header)-payloadLen]

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketMissingPayload) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketMissingPayload, err)
	}

	// 5. Bad header (incomplete SOCKS address)
	header = header[:len(header)-1]

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Expected: %s\nGot: %s", io.ErrShortBuffer, err)
	}

	// 6. Bad header (incomplete padding)
	header = header[:len(header)-len(targetAddrHttps)]

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 7. Bad header (padding length out of range)
	binary.BigEndian.PutUint16(header[1+8+8:], MaxPaddingLength+1)

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPaddingLengthOutOfRange) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPaddingLengthOutOfRange, err)
	}

	// 8. Bad header (incomplete padding length)
	header = header[:1+8+8+1]

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrPacketIncompleteHeader) {
		t.Fatalf("Expected: %s\nGot: %s", ErrPacketIncompleteHeader, err)
	}

	// 9. Bad client session ID
	header = header[:UDPServerMessageHeaderFixedLength]
	badCsid := csid + 1
	binary.BigEndian.PutUint64(header[1+8:], badCsid)

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrClientSessionIDMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrClientSessionIDMismatch, err)
	}

	// 10. Bad timestamp (31s ago)
	ts := time.Now().Add(-31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 11. Bad timestamp (31s later)
	ts = time.Now().Add(31 * time.Second)
	binary.BigEndian.PutUint64(header[1:], uint64(ts.Unix()))

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("Expected: %s\nGot: %s", ErrBadTimestamp, err)
	}

	// 12. Bad type
	header[0] = HeaderTypeClientPacket

	_, _, err = ParseUDPServerMessageHeader(header, csid)
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("Expected: %s\nGot: %s", ErrTypeMismatch, err)
	}
}

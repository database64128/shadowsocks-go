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
	targetAddress := targetAddr.String()
	bufLen := TCPRequestVariableLengthHeaderNoPayloadMaxLength + payloadLen
	b := make([]byte, bufLen)

	// 1. Good header (with initial payload)
	n := WriteTCPRequestVariableLengthHeader(b, targetAddr, payload)
	header := b[:n]

	address, p, err := ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if address != targetAddress {
		t.Fatalf("Expected target address %s, got %s", targetAddress, address)
	}

	// 2. Good header (no payload)
	n = WriteTCPRequestVariableLengthHeader(b, targetAddr, nil)
	header = b[:n]

	address, p, err = ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 0 {
		t.Fatalf("Expected empty initial payload, got length %d", len(p))
	}
	if address != targetAddress {
		t.Fatalf("Expected target address %s, got %s", targetAddress, address)
	}

	// 3. Good header (padding + payload)
	n += copy(b[n:], payload)
	header = b[:n]

	address, p, err = ParseTCPRequestVariableLengthHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, payload) {
		t.Fatalf("Expected payload %v\nGot: %v", payload, p)
	}
	if address != targetAddress {
		t.Fatalf("Expected target address %s, got %s", targetAddress, address)
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

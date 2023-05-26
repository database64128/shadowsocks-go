package ss2022

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
)

const (
	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1

	HeaderTypeClientPacket = 0
	HeaderTypeServerPacket = 1

	MinPaddingLength = 0
	MaxPaddingLength = 900

	IdentityHeaderLength = 16

	// type + unix epoch timestamp + u16be length
	TCPRequestFixedLengthHeaderLength = 1 + 8 + 2

	// SOCKS address + padding length + padding
	TCPRequestVariableLengthHeaderNoPayloadMaxLength = socks5.MaxAddrLen + 2 + MaxPaddingLength

	// type + unix epoch timestamp + request salt + u16be length
	TCPResponseHeaderMaxLength = 1 + 8 + 32 + 2

	// session ID + packet ID
	UDPSeparateHeaderLength = 8 + 8

	// type + unix epoch timestamp + padding length
	UDPClientMessageHeaderFixedLength = 1 + 8 + 2

	// type + unix epoch timestamp + client session id + padding length
	UDPServerMessageHeaderFixedLength = 1 + 8 + 8 + 2

	// type + unix epoch timestamp + padding length + padding + SOCKS address
	UDPClientMessageHeaderMaxLength = UDPClientMessageHeaderFixedLength + MaxPaddingLength + socks5.MaxAddrLen

	// type + unix epoch timestamp + client session id + padding length + padding + SOCKS address
	UDPServerMessageHeaderMaxLength = UDPServerMessageHeaderFixedLength + MaxPaddingLength + socks5.IPv6AddrLen

	// MaxEpochDiff is the maximum allowed time difference between a received timestamp and system time.
	MaxEpochDiff = 30

	// MaxTimeDiff is the maximum allowed time difference between a received timestamp and system time.
	MaxTimeDiff = MaxEpochDiff * time.Second

	// ReplayWindowDuration defines the amount of time during which a salt check is necessary.
	ReplayWindowDuration = MaxTimeDiff * 2

	// DefaultSlidingWindowFilterSize is the default size of the sliding window filter.
	DefaultSlidingWindowFilterSize = 256
)

var (
	ErrIncompleteHeaderInFirstChunk  = errors.New("header in first chunk is missing or incomplete")
	ErrPaddingExceedChunkBorder      = errors.New("padding in first chunk is shorter than advertised")
	ErrBadTimestamp                  = errors.New("time diff is over 30 seconds")
	ErrTypeMismatch                  = errors.New("header type mismatch")
	ErrClientSaltMismatch            = errors.New("client salt in response header does not match request")
	ErrClientSessionIDMismatch       = errors.New("client session ID in server message header does not match current session")
	ErrTooManyServerSessions         = errors.New("server session changed more than once during the last minute")
	ErrPacketIncompleteHeader        = errors.New("packet contains incomplete header")
	ErrReplay                        = errors.New("detected replay")
	ErrIdentityHeaderUserPSKNotFound = errors.New("decrypted identity header does not match any known uPSK")
)

type HeaderError[T any] struct {
	Err      error
	Expected T
	Got      T
}

func (e *HeaderError[T]) Unwrap() error {
	return e.Err
}

func (e *HeaderError[T]) Error() string {
	return fmt.Sprintf("%s: expected %v, got %v", e.Err.Error(), e.Expected, e.Got)
}

// ValidateUnixEpochTimestamp validates the Unix Epoch timestamp in the buffer
// and returns an error if the timestamp exceeds the allowed time difference from system time.
//
// This function does not check buffer length. Make sure it's exactly 8 bytes long.
func ValidateUnixEpochTimestamp(b []byte) error {
	tsEpoch := int64(binary.BigEndian.Uint64(b))
	nowEpoch := time.Now().Unix()
	diff := tsEpoch - nowEpoch
	if diff < -MaxEpochDiff || diff > MaxEpochDiff {
		return &HeaderError[int64]{ErrBadTimestamp, nowEpoch, tsEpoch}
	}
	return nil
}

func intToUint16(i int) (u uint16) {
	u = uint16(i)
	if int(u) != i {
		panic("int -> uint16 overflowed: " + strconv.Itoa(i))
	}
	return
}

// ParseTCPRequestFixedLengthHeader parses a TCP request fixed-length header and returns the length
// of the variable-length header, or an error if header validation fails.
//
// The buffer must be exactly 11 bytes long. No buffer length checks are performed.
//
// Request fixed-length header:
//
//	+------+---------------+--------+
//	| type |   timestamp   | length |
//	+------+---------------+--------+
//	|  1B  | 8B unix epoch |  u16be |
//	+------+---------------+--------+
func ParseTCPRequestFixedLengthHeader(b []byte) (n int, err error) {
	// Type
	if b[0] != HeaderTypeClientStream {
		err = &HeaderError[byte]{ErrTypeMismatch, HeaderTypeClientStream, b[0]}
		return
	}

	// Timestamp
	err = ValidateUnixEpochTimestamp(b[1:])
	if err != nil {
		return
	}

	// Length
	n = int(binary.BigEndian.Uint16(b[1+8:]))

	return
}

// WriteTCPRequestFixedLengthHeader writes a TCP request fixed-length header into the buffer.
//
// The buffer must be at least 11 bytes long. No buffer length checks are performed.
func WriteTCPRequestFixedLengthHeader(b []byte, length uint16) {
	// Type
	b[0] = HeaderTypeClientStream

	// Timestamp
	binary.BigEndian.PutUint64(b[1:], uint64(time.Now().Unix()))

	// Length
	binary.BigEndian.PutUint16(b[1+8:], length)
}

// ParseTCPRequestVariableLengthHeader parses a TCP request variable-length header and returns
// the target address, the initial payload if available, or an error if header validation fails.
//
// This function does buffer length checks and returns ErrIncompleteHeaderInFirstChunk if the buffer is too short.
//
// Request variable-length header:
//
//	+------+----------+-------+----------------+----------+-----------------+
//	| ATYP |  address |  port | padding length |  padding | initial payload |
//	+------+----------+-------+----------------+----------+-----------------+
//	|  1B  | variable | u16be |     u16be      | variable |    variable     |
//	+------+----------+-------+----------------+----------+-----------------+
func ParseTCPRequestVariableLengthHeader(b []byte) (targetAddr conn.Addr, payload []byte, err error) {
	// SOCKS address
	targetAddr, n, err := socks5.ConnAddrFromSlice(b)
	if err != nil {
		return
	}
	b = b[n:]

	// Make sure the remaining length > 2 (padding length + either padding or payload)
	if len(b) <= 2 {
		err = ErrIncompleteHeaderInFirstChunk
		return
	}

	// Padding length
	paddingLen := int(binary.BigEndian.Uint16(b))

	// Padding
	if 2+paddingLen > len(b) {
		err = &HeaderError[int]{ErrPaddingExceedChunkBorder, len(b), 2 + paddingLen}
		return
	}

	// Initial payload
	payload = b[2+paddingLen:]

	return
}

// WriteTCPRequestVariableLengthHeader writes a TCP request variable-length header into the buffer.
//
// The header fills the whole buffer. Excess bytes are used as padding.
//
// The buffer size can be calculated with:
//
//	socks5.LengthOfAddrFromConnAddr(targetAddr) + 2 + len(payload) + paddingLen
//
// The buffer size must not exceed [MaxPayloadSize].
// The excess space in the buffer must not be larger than [MaxPaddingLength] bytes.
func WriteTCPRequestVariableLengthHeader(b []byte, targetAddr conn.Addr, payload []byte) {
	// SOCKS address
	n := socks5.WriteAddrFromConnAddr(b, targetAddr)

	// Padding length
	paddingLen := len(b) - n - 2 - len(payload)
	binary.BigEndian.PutUint16(b[n:], intToUint16(paddingLen))
	n += 2 + paddingLen

	// Initial payload
	copy(b[n:], payload)
}

// ParseTCPResponseHeader parses a TCP response fixed-length header and returns the length
// of the next payload chunk, or an error if header validation fails.
//
// The buffer must be exactly 1 + 8 + salt length + 2 bytes long. No buffer length checks are performed.
//
// Response fixed-length header:
//
//	+------+---------------+----------------+--------+
//	| type |   timestamp   |  request salt  | length |
//	+------+---------------+----------------+--------+
//	|  1B  | 8B unix epoch |     16/32B     |  u16be |
//	+------+---------------+----------------+--------+
func ParseTCPResponseHeader(b []byte, requestSalt []byte) (n int, err error) {
	// Type
	if b[0] != HeaderTypeServerStream {
		err = &HeaderError[byte]{ErrTypeMismatch, HeaderTypeServerStream, b[0]}
		return
	}

	// Timestamp
	err = ValidateUnixEpochTimestamp(b[1 : 1+8])
	if err != nil {
		return
	}

	// Request salt
	rSalt := b[1+8 : 1+8+len(requestSalt)]
	if !bytes.Equal(requestSalt, rSalt) {
		err = &HeaderError[[]byte]{ErrClientSaltMismatch, requestSalt, rSalt}
		return
	}

	// Length
	n = int(binary.BigEndian.Uint16(b[1+8+len(requestSalt):]))

	return
}

// WriteTCPResponseHeader writes a TCP response fixed-length header into the buffer.
//
// The buffer size must be exactly 1 + 8 + len(requestSalt) + 2 bytes.
func WriteTCPResponseHeader(b []byte, requestSalt []byte, length uint16) {
	// Type
	b[0] = HeaderTypeServerStream

	// Timestamp
	binary.BigEndian.PutUint64(b[1:], uint64(time.Now().Unix()))

	// Request salt
	copy(b[1+8:], requestSalt)

	// Length
	binary.BigEndian.PutUint16(b[1+8+len(requestSalt):], length)
}

// ParseSessionIDAndPacketID parses the session ID and packet ID segment of a decrypted UDP packet.
//
// The buffer must be exactly 16 bytes long. No buffer length checks are performed.
//
// Session ID and packet ID segment:
//
//	+------------+-----------+
//	| session ID | packet ID |
//	+------------+-----------+
//	|     8B     |   u64be   |
//	+------------+-----------+
func ParseSessionIDAndPacketID(b []byte) (sid, pid uint64) {
	sid = binary.BigEndian.Uint64(b)
	pid = binary.BigEndian.Uint64(b[8:])
	return
}

// WriteSessionIDAndPacketID writes the session ID and packet ID to the buffer.
//
// The buffer must be exactly 16 bytes long. No buffer length checks are performed.
func WriteSessionIDAndPacketID(b []byte, sid, pid uint64) {
	binary.BigEndian.PutUint64(b, sid)
	binary.BigEndian.PutUint64(b[8:], pid)
}

// ParseUDPClientMessageHeader parses a UDP client message header and returns the target address
// and payload, or an error if header validation fails or no payload is in the buffer.
//
// This function accepts buffers of arbitrary lengths.
//
// The buffer is expected to contain a decrypted client message in the following format:
//
//	+------+---------------+----------------+----------+------+----------+-------+----------+
//	| type |   timestamp   | padding length |  padding | ATYP |  address |  port |  payload |
//	+------+---------------+----------------+----------+------+----------+-------+----------+
//	|  1B  | 8B unix epoch |     u16be      | variable |  1B  | variable | u16be | variable |
//	+------+---------------+----------------+----------+------+----------+-------+----------+
func ParseUDPClientMessageHeader(b []byte, cachedDomain string) (targetAddr conn.Addr, updatedCachedDomain string, payloadStart, payloadLen int, err error) {
	updatedCachedDomain = cachedDomain

	// Make sure buffer has type + timestamp + padding length.
	if len(b) < UDPClientMessageHeaderFixedLength {
		err = ErrPacketIncompleteHeader
		return
	}

	// Type
	if b[0] != HeaderTypeClientPacket {
		err = &HeaderError[byte]{ErrTypeMismatch, HeaderTypeClientPacket, b[0]}
		return
	}

	// Timestamp
	err = ValidateUnixEpochTimestamp(b[1 : 1+8])
	if err != nil {
		return
	}

	// Padding length
	paddingLen := int(binary.BigEndian.Uint16(b[1+8:]))

	// Padding
	payloadStart = UDPClientMessageHeaderFixedLength + paddingLen
	if payloadStart > len(b) {
		err = ErrPacketIncompleteHeader
		return
	}

	// SOCKS address
	var n int
	targetAddr, n, updatedCachedDomain, err = socks5.ConnAddrFromSliceWithDomainCache(b[payloadStart:], cachedDomain)
	if err != nil {
		return
	}

	// Payload
	payloadStart += n
	payloadLen = len(b) - payloadStart
	return
}

// WriteUDPClientMessageHeader writes a UDP client message header into the buffer.
//
// The buffer size must be exactly 1 + 8 + 2 + paddingLen + socks5.LengthOfAddrFromConnAddr(targetAddr) bytes.
func WriteUDPClientMessageHeader(b []byte, paddingLen int, targetAddr conn.Addr) {
	// Type
	b[0] = HeaderTypeClientPacket

	// Timestamp
	binary.BigEndian.PutUint64(b[1:], uint64(time.Now().Unix()))

	// Padding length
	binary.BigEndian.PutUint16(b[1+8:], intToUint16(paddingLen))

	// SOCKS address
	socks5.WriteAddrFromConnAddr(b[1+8+2+paddingLen:], targetAddr)
}

// ParseUDPServerMessageHeader parses a UDP server message header and returns the payload source address
// and payload, or an error if header validation fails or no payload is in the buffer.
//
// This function accepts buffers of arbitrary lengths.
//
// The buffer is expected to contain a decrypted server message in the following format:
//
//	+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
//	| type |   timestamp   | client session ID | padding length |  padding | ATYP |  address |  port |  payload |
//	+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
//	|  1B  | 8B unix epoch |         8B        |     u16be      | variable |  1B  | variable | u16be | variable |
//	+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
func ParseUDPServerMessageHeader(b []byte, csid uint64) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
	// Make sure buffer has type + timestamp + client session ID + padding length.
	if len(b) < UDPServerMessageHeaderFixedLength {
		err = ErrPacketIncompleteHeader
		return
	}

	// Type
	if b[0] != HeaderTypeServerPacket {
		err = &HeaderError[byte]{ErrTypeMismatch, HeaderTypeServerPacket, b[0]}
		return
	}

	// Timestamp
	err = ValidateUnixEpochTimestamp(b[1 : 1+8])
	if err != nil {
		return
	}

	// Client session ID
	pcsid := binary.BigEndian.Uint64(b[1+8:])
	if pcsid != csid {
		err = &HeaderError[uint64]{ErrClientSessionIDMismatch, csid, pcsid}
		return
	}

	// Padding length
	paddingLen := int(binary.BigEndian.Uint16(b[1+8+8:]))

	// Padding
	payloadStart = UDPServerMessageHeaderFixedLength + paddingLen
	if payloadStart > len(b) {
		err = ErrPacketIncompleteHeader
		return
	}

	// SOCKS address
	payloadSourceAddrPort, n, err := socks5.AddrPortFromSlice(b[payloadStart:])
	if err != nil {
		return
	}

	// Payload
	payloadStart += n
	payloadLen = len(b) - payloadStart
	return
}

// WriteUDPServerMessageHeader writes a UDP server message header into the buffer.
//
// The buffer size must be exactly 1 + 8 + 8 + 2 + paddingLen + socks5.LengthOfAddrFromAddrPort(sourceAddrPort) bytes.
func WriteUDPServerMessageHeader(b []byte, csid uint64, paddingLen int, sourceAddrPort netip.AddrPort) {
	// Type
	b[0] = HeaderTypeServerPacket

	// Timestamp
	binary.BigEndian.PutUint64(b[1:], uint64(time.Now().Unix()))

	// Client session ID
	binary.BigEndian.PutUint64(b[1+8:], csid)

	// Padding length
	binary.BigEndian.PutUint16(b[1+8+8:], intToUint16(paddingLen))

	// SOCKS address
	socks5.WriteAddrFromAddrPort(b[1+8+8+2+paddingLen:], sourceAddrPort)
}

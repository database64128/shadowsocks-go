package ss2022

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/database64128/shadowsocks-go/magic"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type ShadowPacketReplayError struct {
	// Session ID.
	sid uint64

	// Packet ID.
	pid uint64
}

func (e *ShadowPacketReplayError) Unwrap() error {
	return ErrReplay
}

func (e *ShadowPacketReplayError) Error() string {
	return fmt.Sprintf("detected replay packet: session ID %d, packet ID %d", e.sid, e.pid)
}

// ShadowPacketClientPacker packs UDP packets into authenticated and encrypted
// Shadowsocks packets.
//
// ShadowPacketClientPacker implements the zerocopy.Packer interface.
//
// Packet format:
// 	+---------------------------+-----+-----+---------------------------+
// 	| encrypted separate header | EIH | ... |       encrypted body      |
// 	+---------------------------+-----+-----+---------------------------+
// 	|            16B            | 16B | ... | variable length + 16B tag |
// 	+---------------------------+-----+-----+---------------------------+
type ShadowPacketClientPacker struct {
	// Client session ID.
	csid uint64

	// Client packet ID.
	cpid uint64

	// Body AEAD cipher.
	aead cipher.AEAD

	// Block cipher for the separate header.
	block cipher.Block

	// Padding policy.
	shouldPad PaddingPolicy

	// EIH block ciphers.
	// Must include a cipher for each iPSK.
	// Must have the same length as eihPSKHashes.
	eihCiphers []cipher.Block

	// EIH PSK hashes.
	// These are first 16 bytes of BLAKE3 hashes of iPSK1 all the way up to uPSK.
	// Must have the same length as eihCiphers.
	eihPSKHashes [][IdentityHeaderLength]byte
}

// FrontHeadroom implements the Packer FrontHeadroom method.
func (p *ShadowPacketClientPacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + IdentityHeaderLength*len(p.eihCiphers) + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the Packer RearHeadroom method.
func (p *ShadowPacketClientPacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// PackInPlace implements the Packer PackInPlace method.
func (p *ShadowPacketClientPacker) PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	nonAEADHeaderLength := UDPSeparateHeaderLength + IdentityHeaderLength*len(p.eihCiphers)
	messageHeaderLengthBudget := maxPacketLen - payloadLen - nonAEADHeaderLength - p.aead.Overhead()
	if messageHeaderLengthBudget < UDPClientMessageHeaderFixedLength+len(targetAddr) {
		err = zerocopy.ErrPayloadTooBig
		return
	}
	messageHeaderBufSize := payloadStart - nonAEADHeaderLength
	if messageHeaderBufSize > messageHeaderLengthBudget {
		messageHeaderBufSize = messageHeaderLengthBudget
	}

	// Write message header.
	n, err := WriteUDPClientMessageHeader(b[payloadStart-messageHeaderBufSize:payloadStart], targetAddr, p.shouldPad)
	if err != nil {
		return
	}

	messageHeaderStart := payloadStart - n
	packetStart = messageHeaderStart - nonAEADHeaderLength
	packetLen = nonAEADHeaderLength + n + payloadLen + p.aead.Overhead()
	identityHeadersStart := packetStart + UDPSeparateHeaderLength
	separateHeader := b[packetStart:identityHeadersStart]
	nonce := separateHeader[4:16]
	plaintext := b[messageHeaderStart : payloadStart+payloadLen]

	// Write separate header.
	WriteSessionIDAndPacketID(separateHeader, p.csid, p.cpid)
	p.cpid++

	// Write and encrypt identity headers.
	for i := range p.eihCiphers {
		start := identityHeadersStart + i*IdentityHeaderLength
		identityHeader := b[start : start+IdentityHeaderLength]
		magic.XORWords(identityHeader, p.eihPSKHashes[i][:], separateHeader)
		p.eihCiphers[i].Encrypt(identityHeader, identityHeader)
	}

	// AEAD seal.
	p.aead.Seal(plaintext[:0], nonce, plaintext, nil)

	// Block encrypt.
	p.block.Encrypt(separateHeader, separateHeader)

	return
}

// ShadowPacketServerPacker packs UDP packets into authenticated and encrypted
// Shadowsocks packets.
//
// ShadowPacketServerPacker implements the zerocopy.Packer interface.
type ShadowPacketServerPacker struct {
	// Server session ID.
	ssid uint64

	// Server packet ID.
	spid uint64

	// Client session ID.
	csid uint64

	// Body AEAD cipher.
	aead cipher.AEAD

	// Block cipher for the separate header.
	block cipher.Block

	// Padding policy.
	shouldPad PaddingPolicy
}

// FrontHeadroom implements the Packer FrontHeadroom method.
func (p *ShadowPacketServerPacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + UDPServerMessageHeaderMaxLength
}

// RearHeadroom implements the Packer RearHeadroom method.
func (p *ShadowPacketServerPacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// PackInPlace implements the Packer PackInPlace method.
func (p *ShadowPacketServerPacker) PackInPlace(b []byte, targetAddr socks5.Addr, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	messageHeaderLengthBudget := maxPacketLen - payloadLen - UDPSeparateHeaderLength - p.aead.Overhead()
	if messageHeaderLengthBudget < UDPServerMessageHeaderFixedLength+len(targetAddr) {
		err = zerocopy.ErrPayloadTooBig
		return
	}
	messageHeaderBufSize := payloadStart - UDPSeparateHeaderLength
	if messageHeaderBufSize > messageHeaderLengthBudget {
		messageHeaderBufSize = messageHeaderLengthBudget
	}

	// Write message header.
	n, err := WriteUDPServerMessageHeader(b[payloadStart-messageHeaderBufSize:payloadStart], p.csid, targetAddr, p.shouldPad)
	if err != nil {
		return
	}

	messageHeaderStart := payloadStart - n
	packetStart = messageHeaderStart - UDPSeparateHeaderLength
	packetLen = UDPSeparateHeaderLength + n + payloadLen + p.aead.Overhead()
	separateHeader := b[packetStart:messageHeaderStart]
	nonce := separateHeader[4:16]
	plaintext := b[messageHeaderStart : payloadStart+payloadLen]

	// Write separate header.
	WriteSessionIDAndPacketID(separateHeader, p.ssid, p.spid)
	p.spid++

	// AEAD seal.
	p.aead.Seal(plaintext[:0], nonce, plaintext, nil)

	// Block encrypt.
	p.block.Encrypt(separateHeader, separateHeader)

	return
}

// ShadowPacketClientUnpacker unpacks Shadowsocks server packets and returns
// target address and plaintext payload.
//
// When a server session changes, there's a replay window of less than 60 seconds,
// during which an adversary can replay packets with a valid timestamp from the old session.
// To protect against such attacks, and to simplify implementation and save resources,
// we only save information for one previous session.
//
// In an unlikely event where the server session changed more than once within 60s,
// we simply drop new server sessions.
//
// ShadowPacketClientUnpacker implements the zerocopy.Unpacker interface.
type ShadowPacketClientUnpacker struct {
	// Client session ID.
	csid uint64

	// Current server session ID.
	currentServerSessionID uint64

	// Current server session AEAD cipher.
	currentServerSessionAEAD cipher.AEAD

	// Current server session sliding window filter.
	currentServerSessionFilter *Filter

	// Old server session ID.
	oldServerSessionID uint64

	// Old server session AEAD cipher.
	oldServerSessionAEAD cipher.AEAD

	// Old server session sliding window filter.
	oldServerSessionFilter *Filter

	// Old server session last seen time.
	oldServerSessionLastSeenTime time.Time

	// Block cipher for the separate header.
	block cipher.Block

	// Cipher config.
	cipherConfig *CipherConfig
}

// FrontHeadroom implements the Unpacker FrontHeadroom method.
func (p *ShadowPacketClientUnpacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + UDPServerMessageHeaderMaxLength
}

// RearHeadroom implements the Unpacker RearHeadroom method.
func (p *ShadowPacketClientUnpacker) RearHeadroom() int {
	return 16
}

// UnpackInPlace implements the Unpacker UnpackInPlace method.
func (p *ShadowPacketClientUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error) {
	const (
		currentServerSession = iota
		oldServerSession
		newServerSession
	)

	var (
		ssid          uint64
		spid          uint64
		saead         cipher.AEAD
		sfilter       *Filter
		sessionStatus int
	)

	// Check length.
	if packetLen < UDPSeparateHeaderLength+16 {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	messageHeaderStart := packetStart + UDPSeparateHeaderLength
	separateHeader := b[packetStart:messageHeaderStart]
	nonce := separateHeader[4:16]
	ciphertext := b[messageHeaderStart : packetStart+packetLen]

	// Decrypt separate header.
	p.block.Decrypt(separateHeader, separateHeader)

	// Determine session status.
	ssid = binary.BigEndian.Uint64(separateHeader)
	spid = binary.BigEndian.Uint64(separateHeader[8:])
	switch {
	case ssid == p.currentServerSessionID && p.currentServerSessionAEAD != nil:
		saead = p.currentServerSessionAEAD
		sfilter = p.currentServerSessionFilter
		sessionStatus = currentServerSession
	case ssid == p.oldServerSessionID && p.oldServerSessionAEAD != nil:
		saead = p.oldServerSessionAEAD
		sfilter = p.oldServerSessionFilter
		sessionStatus = oldServerSession
	case time.Since(p.oldServerSessionLastSeenTime) < time.Minute:
		// Reject fast-changing server sessions.
		err = ErrTooManyServerSessions
		return
	default:
		// Likely a new server session.
		// Delay sfilter creation after validation to avoid a possibly unnecessary allocation.
		saead = p.cipherConfig.NewAEAD(separateHeader[:8])
		sessionStatus = newServerSession
	}

	// Check spid.
	if sfilter != nil && !sfilter.IsOk(spid) {
		err = &ShadowPacketReplayError{ssid, spid}
		return
	}

	// AEAD open.
	plaintext, err := saead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Parse message header.
	targetAddr, payloadStart, payloadLen, err = ParseUDPServerMessageHeader(plaintext, p.csid)
	if err != nil {
		return
	}
	hasTargetAddr = true
	payloadStart += messageHeaderStart

	// Add spid to filter.
	if sessionStatus == newServerSession {
		sfilter = &Filter{}
	}
	sfilter.MustAdd(spid)

	// Update session status.
	switch sessionStatus {
	case oldServerSession:
		p.oldServerSessionLastSeenTime = time.Now()
	case newServerSession:
		p.oldServerSessionID = p.currentServerSessionID
		p.oldServerSessionAEAD = p.currentServerSessionAEAD
		p.oldServerSessionFilter = p.currentServerSessionFilter
		p.oldServerSessionLastSeenTime = time.Now()
		p.currentServerSessionID = ssid
		p.currentServerSessionAEAD = saead
		p.currentServerSessionFilter = sfilter
	}

	return
}

// ShadowPacketServerUnpacker unpacks Shadowsocks client packets and returns
// target address and plaintext payload.
//
// ShadowPacketServerUnpacker implements the zerocopy.Unpacker interface.
type ShadowPacketServerUnpacker struct {
	// Client session ID.
	csid uint64

	// Body AEAD cipher.
	aead cipher.AEAD

	// Client session sliding window filter.
	//
	// This filter instance should be created during the first successful unpack operation.
	// We trade 2 extra nil checks during unpacking for better performance when the server is flooded by invalid packets.
	filter *Filter

	// Whether incoming packets have an identity header.
	hasEIH bool
}

// FrontHeadroom implements the Unpacker FrontHeadroom method.
func (p *ShadowPacketServerUnpacker) FrontHeadroom() int {
	var identityHeaderLen int
	if p.hasEIH {
		identityHeaderLen = IdentityHeaderLength
	}
	return UDPSeparateHeaderLength + identityHeaderLen + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the Unpacker RearHeadroom method.
func (p *ShadowPacketServerUnpacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// UnpackInPlace unpacks the AEAD encrypted part of a Shadowsocks client packet
// and returns target address, payload start offset and payload length, or an error.
//
// UnpackInPlace implements the Unpacker UnpackInPlace method.
func (p *ShadowPacketServerUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (targetAddr socks5.Addr, hasTargetAddr bool, payloadStart, payloadLen int, err error) {
	var identityHeaderLen int
	if p.hasEIH {
		identityHeaderLen = IdentityHeaderLength
	}

	// Check length.
	if packetLen < UDPSeparateHeaderLength+identityHeaderLen+p.aead.Overhead() {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	messageHeaderStart := packetStart + UDPSeparateHeaderLength + identityHeaderLen
	separateHeader := b[packetStart : packetStart+UDPSeparateHeaderLength]
	nonce := separateHeader[4:16]
	ciphertext := b[messageHeaderStart : packetStart+packetLen]

	// Check cpid.
	cpid := binary.BigEndian.Uint64(separateHeader[8:])
	if p.filter != nil && !p.filter.IsOk(cpid) {
		err = &ShadowPacketReplayError{p.csid, cpid}
		return
	}

	// AEAD open.
	plaintext, err := p.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Parse message header.
	targetAddr, payloadStart, payloadLen, err = ParseUDPClientMessageHeader(plaintext)
	if err != nil {
		return
	}
	hasTargetAddr = true
	payloadStart += messageHeaderStart

	// Add cpid to filter.
	if p.filter == nil {
		p.filter = &Filter{}
	}
	p.filter.MustAdd(cpid)

	return
}

package ss2022

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/magic"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type ShadowPacketReplayError struct {
	// Source address.
	srcAddr netip.AddrPort

	// Session ID.
	sid uint64

	// Packet ID.
	pid uint64
}

func (e *ShadowPacketReplayError) Unwrap() error {
	return ErrReplay
}

func (e *ShadowPacketReplayError) Error() string {
	return fmt.Sprintf("received replay packet from %s: session ID %d, packet ID %d", e.srcAddr, e.sid, e.pid)
}

// ShadowPacketClientPacker packs UDP packets into authenticated and encrypted
// Shadowsocks packets.
//
// ShadowPacketClientPacker implements the zerocopy.Packer interface.
//
// Packet format:
//
//	+---------------------------+-----+-----+---------------------------+
//	| encrypted separate header | EIH | ... |       encrypted body      |
//	+---------------------------+-----+-----+---------------------------+
//	|            16B            | 16B | ... | variable length + 16B tag |
//	+---------------------------+-----+-----+---------------------------+
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

	// maxPacketSize is the maximum allowed size of a packed packet.
	// The value is calculated from MTU and server address family.
	maxPacketSize int

	// serverAddrPort is the Shadowsocks server's address.
	serverAddrPort netip.AddrPort
}

// FrontHeadroom implements the zerocopy.ClientPacker FrontHeadroom method.
func (p *ShadowPacketClientPacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + IdentityHeaderLength*len(p.eihCiphers) + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the zerocopy.ClientPacker RearHeadroom method.
func (p *ShadowPacketClientPacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *ShadowPacketClientPacker) PackInPlace(b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	nonAEADHeaderLen := UDPSeparateHeaderLength + IdentityHeaderLength*len(p.eihCiphers)
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	headerNoPaddingLen := nonAEADHeaderLen + UDPClientMessageHeaderFixedLength + targetAddrLen
	maxPaddingLen := p.maxPacketSize - headerNoPaddingLen - payloadLen - p.aead.Overhead()
	if mpl := payloadStart - headerNoPaddingLen; mpl < maxPaddingLen {
		maxPaddingLen = mpl
	}
	if maxPaddingLen > math.MaxUint16 {
		maxPaddingLen = math.MaxUint16
	}

	var paddingLen int

	switch {
	case maxPaddingLen < 0:
		err = zerocopy.ErrPayloadTooBig
		return
	case maxPaddingLen > 0 && p.shouldPad(targetAddr):
		paddingLen = 1 + rand.Intn(maxPaddingLen)
	}

	messageHeaderStart := payloadStart - UDPClientMessageHeaderFixedLength - targetAddrLen - paddingLen

	// Write message header.
	WriteUDPClientMessageHeader(b[messageHeaderStart:payloadStart], paddingLen, targetAddr)

	destAddrPort = p.serverAddrPort
	packetStart = messageHeaderStart - nonAEADHeaderLen
	packetLen = payloadStart - packetStart + payloadLen + p.aead.Overhead()
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

// FrontHeadroom implements the zerocopy.ServerPacker FrontHeadroom method.
func (p *ShadowPacketServerPacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + UDPServerMessageHeaderMaxLength
}

// RearHeadroom implements the zerocopy.ServerPacker RearHeadroom method.
func (p *ShadowPacketServerPacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// PackInPlace implements the zerocopy.ServerPacker PackInPlace method.
func (p *ShadowPacketServerPacker) PackInPlace(b []byte, sourceAddrPort netip.AddrPort, payloadStart, payloadLen, maxPacketLen int) (packetStart, packetLen int, err error) {
	sourceAddrLen := socks5.LengthOfAddrFromAddrPort(sourceAddrPort)
	headerNoPaddingLen := UDPSeparateHeaderLength + UDPServerMessageHeaderFixedLength + sourceAddrLen
	maxPaddingLen := maxPacketLen - headerNoPaddingLen - payloadLen - p.aead.Overhead()
	if mpl := payloadStart - headerNoPaddingLen; mpl < maxPaddingLen {
		maxPaddingLen = mpl
	}
	if maxPaddingLen > math.MaxUint16 {
		maxPaddingLen = math.MaxUint16
	}

	var paddingLen int

	switch {
	case maxPaddingLen < 0:
		err = zerocopy.ErrPayloadTooBig
		return
	case maxPaddingLen > 0 && p.shouldPad(conn.AddrFromIPPort(sourceAddrPort)):
		paddingLen = 1 + rand.Intn(maxPaddingLen)
	}

	messageHeaderStart := payloadStart - UDPServerMessageHeaderFixedLength - paddingLen - sourceAddrLen

	// Write message header.
	WriteUDPServerMessageHeader(b[messageHeaderStart:payloadStart], p.csid, paddingLen, sourceAddrPort)

	packetStart = messageHeaderStart - UDPSeparateHeaderLength
	packetLen = payloadStart - packetStart + payloadLen + p.aead.Overhead()
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

// FrontHeadroom implements the zerocopy.ClientUnpacker FrontHeadroom method.
func (p *ShadowPacketClientUnpacker) FrontHeadroom() int {
	return UDPSeparateHeaderLength + UDPServerMessageHeaderMaxLength
}

// RearHeadroom implements the zerocopy.ClientUnpacker RearHeadroom method.
func (p *ShadowPacketClientUnpacker) RearHeadroom() int {
	return 16
}

// UnpackInPlace implements the zerocopy.ClientUnpacker UnpackInPlace method.
func (p *ShadowPacketClientUnpacker) UnpackInPlace(b []byte, packetSourceAddrPort netip.AddrPort, packetStart, packetLen int) (payloadSourceAddrPort netip.AddrPort, payloadStart, payloadLen int, err error) {
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
		err = &ShadowPacketReplayError{packetSourceAddrPort, ssid, spid}
		return
	}

	// AEAD open.
	plaintext, err := saead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Parse message header.
	payloadSourceAddrPort, payloadStart, payloadLen, err = ParseUDPServerMessageHeader(plaintext, p.csid)
	if err != nil {
		return
	}
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

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string
}

// FrontHeadroom implements the zerocopy.ServerUnpacker FrontHeadroom method.
func (p *ShadowPacketServerUnpacker) FrontHeadroom() int {
	var identityHeaderLen int
	if p.hasEIH {
		identityHeaderLen = IdentityHeaderLength
	}
	return UDPSeparateHeaderLength + identityHeaderLen + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the zerocopy.ServerUnpacker RearHeadroom method.
func (p *ShadowPacketServerUnpacker) RearHeadroom() int {
	return p.aead.Overhead()
}

// UnpackInPlace unpacks the AEAD encrypted part of a Shadowsocks client packet
// and returns target address, payload start offset and payload length, or an error.
//
// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *ShadowPacketServerUnpacker) UnpackInPlace(b []byte, sourceAddr netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
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
		err = &ShadowPacketReplayError{sourceAddr, p.csid, cpid}
		return
	}

	// AEAD open.
	plaintext, err := p.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Parse message header.
	targetAddr, p.cachedDomain, payloadStart, payloadLen, err = ParseUDPClientMessageHeader(plaintext, p.cachedDomain)
	if err != nil {
		return
	}
	payloadStart += messageHeaderStart

	// Add cpid to filter.
	if p.filter == nil {
		p.filter = &Filter{}
	}
	p.filter.MustAdd(cpid)

	return
}

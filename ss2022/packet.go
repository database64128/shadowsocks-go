package ss2022

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/fastrand"
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

// ShadowPacketClientMessageHeadroom returns the headroom required by an encrypted Shadowsocks client message.
func ShadowPacketClientMessageHeadroom(identityHeadersLen int) zerocopy.Headroom {
	return zerocopy.Headroom{
		Front: UDPSeparateHeaderLength + identityHeadersLen + UDPClientMessageHeaderMaxLength,
		Rear:  16,
	}
}

// ShadowPacketServerMessageHeadroom is the headroom required by an encrypted Shadowsocks server message.
var ShadowPacketServerMessageHeadroom = zerocopy.Headroom{
	Front: UDPSeparateHeaderLength + UDPServerMessageHeaderMaxLength,
	Rear:  16,
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

	// nonAEADHeaderLen is the length of the separate header and identity headers.
	nonAEADHeaderLen int

	// info is the client packer info.
	info zerocopy.ClientPackerInfo

	// serverAddrPort is the Shadowsocks server's address.
	serverAddrPort netip.AddrPort
}

// ClientPackerInfo implements the zerocopy.ClientPacker ClientPackerInfo method.
func (p *ShadowPacketClientPacker) ClientPackerInfo() zerocopy.ClientPackerInfo {
	return p.info
}

// PackInPlace implements the zerocopy.ClientPacker PackInPlace method.
func (p *ShadowPacketClientPacker) PackInPlace(ctx context.Context, b []byte, targetAddr conn.Addr, payloadStart, payloadLen int) (destAddrPort netip.AddrPort, packetStart, packetLen int, err error) {
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	headerNoPaddingLen := p.nonAEADHeaderLen + UDPClientMessageHeaderFixedLength + targetAddrLen
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
		paddingLen = 1 + int(fastrand.Uint32n(uint32(maxPaddingLen)))
	}

	messageHeaderStart := payloadStart - UDPClientMessageHeaderFixedLength - targetAddrLen - paddingLen

	// Write message header.
	WriteUDPClientMessageHeader(b[messageHeaderStart:payloadStart], paddingLen, targetAddr)

	destAddrPort = p.serverAddrPort
	packetStart = messageHeaderStart - p.nonAEADHeaderLen
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
		subtle.XORBytes(identityHeader, p.eihPSKHashes[i][:], separateHeader)
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

// ServerPackerInfo implements the zerocopy.ServerPacker ServerPackerInfo method.
func (p *ShadowPacketServerPacker) ServerPackerInfo() zerocopy.ServerPackerInfo {
	return zerocopy.ServerPackerInfo{
		Headroom: ShadowPacketServerMessageHeadroom,
	}
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
		paddingLen = 1 + int(fastrand.Uint32n(uint32(maxPaddingLen)))
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

	// filterSize is the size of the sliding window filter.
	filterSize uint64

	// Current server session ID.
	currentServerSessionID uint64

	// Current server session AEAD cipher.
	currentServerSessionAEAD cipher.AEAD

	// Current server session sliding window filter.
	currentServerSessionFilter *SlidingWindowFilter

	// Old server session ID.
	oldServerSessionID uint64

	// Old server session AEAD cipher.
	oldServerSessionAEAD cipher.AEAD

	// Old server session sliding window filter.
	oldServerSessionFilter *SlidingWindowFilter

	// Old server session last seen time.
	oldServerSessionLastSeenTime time.Time

	// Cipher config.
	cipherConfig *ClientCipherConfig
}

// ClientUnpackerInfo implements the zerocopy.ClientUnpacker ClientUnpackerInfo method.
func (p *ShadowPacketClientUnpacker) ClientUnpackerInfo() zerocopy.ClientUnpackerInfo {
	return zerocopy.ClientUnpackerInfo{
		Headroom: ShadowPacketServerMessageHeadroom,
	}
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
		sfilter       *SlidingWindowFilter
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
	p.cipherConfig.Block().Decrypt(separateHeader, separateHeader)

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
		saead, err = p.cipherConfig.AEAD(separateHeader[:8])
		if err != nil {
			return
		}
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
		sfilter = NewSlidingWindowFilter(p.filterSize)
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
// ShadowPacketServerUnpacker implements the zerocopy.ServerUnpacker interface.
type ShadowPacketServerUnpacker struct {
	// Client session ID.
	csid uint64

	// Body AEAD cipher.
	aead cipher.AEAD

	// filterSize is the size of the sliding window filter.
	filterSize uint64

	// Client session sliding window filter.
	//
	// This filter instance should be created during the first successful unpack operation.
	// We trade 2 extra nil checks during unpacking for better performance when the server is flooded by invalid packets.
	filter *SlidingWindowFilter

	// cachedDomain caches the last used domain target to avoid allocating new strings.
	cachedDomain string

	// nonAEADHeaderLen is the length of the separate header and identity headers.
	nonAEADHeaderLen int

	// info is the server unpacker info.
	info zerocopy.ServerUnpackerInfo

	// userCipherConfig is used when creating a new server packer.
	userCipherConfig UserCipherConfig

	// packerShouldPad is the server packer's padding policy.
	packerShouldPad PaddingPolicy
}

// ServerUnpackerInfo implements the zerocopy.ServerUnpacker ServerUnpackerInfo method.
func (p *ShadowPacketServerUnpacker) ServerUnpackerInfo() zerocopy.ServerUnpackerInfo {
	return p.info
}

// UnpackInPlace unpacks the AEAD encrypted part of a Shadowsocks client packet
// and returns target address, payload start offset and payload length, or an error.
//
// UnpackInPlace implements the zerocopy.ServerUnpacker UnpackInPlace method.
func (p *ShadowPacketServerUnpacker) UnpackInPlace(b []byte, sourceAddr netip.AddrPort, packetStart, packetLen int) (targetAddr conn.Addr, payloadStart, payloadLen int, err error) {
	// Check length.
	if packetLen < p.nonAEADHeaderLen+p.aead.Overhead() {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, packetLen)
		return
	}

	messageHeaderStart := packetStart + p.nonAEADHeaderLen
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
		p.filter = NewSlidingWindowFilter(p.filterSize)
	}
	p.filter.MustAdd(cpid)

	return
}

// NewPacker implements the zerocopy.ServerUnpacker NewPacker method.
func (p *ShadowPacketServerUnpacker) NewPacker() (zerocopy.ServerPacker, error) {
	// Random server session ID.
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	ssid := binary.BigEndian.Uint64(salt)

	aead, err := p.userCipherConfig.AEAD(salt)
	if err != nil {
		return nil, err
	}

	return &ShadowPacketServerPacker{
		ssid:      ssid,
		csid:      p.csid,
		aead:      aead,
		block:     p.userCipherConfig.Block(),
		shouldPad: p.packerShouldPad,
	}, nil
}

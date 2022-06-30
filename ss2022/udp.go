package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/database64128/shadowsocks-go/magic"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	block        cipher.Block
	cipherConfig *CipherConfig
	shouldPad    func(socks5.Addr) bool
	eihCiphers   []cipher.Block
	eihPSKHashes [][IdentityHeaderLength]byte
}

func NewUDPClient(cipherConfig *CipherConfig, shouldPad func(socks5.Addr) bool, eihPSKHashes [][IdentityHeaderLength]byte) *UDPClient {
	eihCiphers := cipherConfig.NewUDPIdentityHeaderClientCiphers()

	var block cipher.Block
	if len(eihCiphers) > 0 {
		block = eihCiphers[0]
	} else {
		block = cipherConfig.NewBlock()
	}

	return &UDPClient{
		block:        block,
		cipherConfig: cipherConfig,
		shouldPad:    shouldPad,
		eihCiphers:   eihCiphers,
		eihPSKHashes: eihPSKHashes,
	}
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *UDPClient) NewSession() (zerocopy.Packer, zerocopy.Unpacker, error) {
	// Random client session ID.
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	csid := binary.BigEndian.Uint64(salt)

	return &ShadowPacketClientPacker{
			csid:         csid,
			aead:         c.cipherConfig.NewAEAD(salt),
			block:        c.block,
			shouldPad:    c.shouldPad,
			eihCiphers:   c.eihCiphers,
			eihPSKHashes: c.eihPSKHashes,
		}, &ShadowPacketClientUnpacker{
			csid:         csid,
			block:        c.block,
			cipherConfig: c.cipherConfig,
		}, nil
}

// UDPServer implements the zerocopy UDPServer interface.
type UDPServer struct {
	block        cipher.Block
	cipherConfig *CipherConfig
	shouldPad    func(socks5.Addr) bool
	uPSKMap      map[[IdentityHeaderLength]byte]*CipherConfig

	// Initialized as the same main cipher config referenced by cipherConfig.
	// Produced by NewSession as the current session's user cipher config.
	// Consumed by a follow-up call to NewPacker.
	currentUserCipherConfig *CipherConfig
}

func NewUDPServer(cipherConfig *CipherConfig, shouldPad func(socks5.Addr) bool, uPSKMap map[[IdentityHeaderLength]byte]*CipherConfig) *UDPServer {
	return &UDPServer{
		block:                   cipherConfig.NewBlock(),
		cipherConfig:            cipherConfig,
		shouldPad:               shouldPad,
		uPSKMap:                 uPSKMap,
		currentUserCipherConfig: cipherConfig,
	}
}

// SessionInfo implements the zerocopy.UDPServer SessionInfo method.
func (s *UDPServer) SessionInfo(b []byte) (csid uint64, err error) {
	if len(b) < UDPSeparateHeaderLength {
		err = fmt.Errorf("%w: %d", ErrPacketTooSmall, len(b))
		return
	}

	s.block.Decrypt(b, b)

	csid = binary.BigEndian.Uint64(b)
	return
}

// NewUnpacker implements the zerocopy.UDPServer NewUnpacker method.
func (s *UDPServer) NewUnpacker(b []byte, csid uint64) (zerocopy.Unpacker, error) {
	var identityHeaderLen int
	hasEIH := len(s.uPSKMap) > 0
	if hasEIH {
		identityHeaderLen = IdentityHeaderLength
	}

	if len(b) < UDPSeparateHeaderLength+identityHeaderLen {
		return nil, fmt.Errorf("%w: %d", ErrPacketTooSmall, len(b))
	}

	// Process identity header.
	if hasEIH {
		separateHeader := b[:UDPSeparateHeaderLength]
		identityHeader := b[UDPSeparateHeaderLength : UDPSeparateHeaderLength+identityHeaderLen]
		s.block.Decrypt(identityHeader, identityHeader)
		magic.XORWords(identityHeader, identityHeader, separateHeader)
		uPSKHash := *(*[IdentityHeaderLength]byte)(identityHeader)
		userCipherConfig, ok := s.uPSKMap[uPSKHash]
		if !ok {
			return nil, ErrIdentityHeaderUserPSKNotFound
		}
		s.currentUserCipherConfig = userCipherConfig
	}

	return &ShadowPacketServerUnpacker{
		csid:   csid,
		aead:   s.currentUserCipherConfig.NewAEAD(b[:8]),
		hasEIH: hasEIH,
	}, nil
}

// NewPacker implements the zerocopy.UDPServer NewPacker method.
func (s *UDPServer) NewPacker(csid uint64) (zerocopy.Packer, error) {
	// Random server session ID.
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	ssid := binary.BigEndian.Uint64(salt)

	return &ShadowPacketServerPacker{
		ssid:      ssid,
		csid:      csid,
		aead:      s.currentUserCipherConfig.NewAEAD(salt),
		block:     s.block,
		shouldPad: s.shouldPad,
	}, nil
}

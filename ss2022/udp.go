package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/magic"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	addrPort      netip.AddrPort
	maxPacketSize int
	fwmark        int
	packerBlock   cipher.Block
	unpackerBlock cipher.Block
	cipherConfig  *CipherConfig
	shouldPad     PaddingPolicy
	eihCiphers    []cipher.Block
	eihPSKHashes  [][IdentityHeaderLength]byte
}

func NewUDPClient(addrPort netip.AddrPort, mtu, fwmark int, cipherConfig *CipherConfig, shouldPad PaddingPolicy, eihPSKHashes [][IdentityHeaderLength]byte) *UDPClient {
	eihCiphers := cipherConfig.NewUDPIdentityHeaderClientCiphers()
	unpackerBlock := cipherConfig.NewBlock()

	var packerBlock cipher.Block
	if len(eihCiphers) > 0 {
		packerBlock = eihCiphers[0]
	} else {
		packerBlock = unpackerBlock
	}

	return &UDPClient{
		addrPort:      addrPort,
		maxPacketSize: zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr()),
		fwmark:        fwmark,
		packerBlock:   packerBlock,
		unpackerBlock: unpackerBlock,
		cipherConfig:  cipherConfig,
		shouldPad:     shouldPad,
		eihCiphers:    eihCiphers,
		eihPSKHashes:  eihPSKHashes,
	}
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *UDPClient) NewSession() (zerocopy.ClientPacker, zerocopy.ClientUnpacker, error) {
	// Random client session ID.
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	csid := binary.BigEndian.Uint64(salt)

	return &ShadowPacketClientPacker{
			csid:           csid,
			aead:           c.cipherConfig.NewAEAD(salt),
			block:          c.packerBlock,
			shouldPad:      c.shouldPad,
			eihCiphers:     c.eihCiphers,
			eihPSKHashes:   c.eihPSKHashes,
			maxPacketSize:  c.maxPacketSize,
			serverAddrPort: c.addrPort,
		}, &ShadowPacketClientUnpacker{
			csid:         csid,
			block:        c.unpackerBlock,
			cipherConfig: c.cipherConfig,
		}, nil
}

// LinkInfo implements the UDPClient LinkInfo method.
func (c *UDPClient) LinkInfo() (int, int) {
	return c.maxPacketSize, c.fwmark
}

// FrontHeadroom implements the UDPClient FrontHeadroom method.
func (c *UDPClient) FrontHeadroom() int {
	return UDPSeparateHeaderLength + IdentityHeaderLength*len(c.eihCiphers) + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the UDPClient RearHeadroom method.
func (c *UDPClient) RearHeadroom() int {
	return 16
}

// UDPServer implements the zerocopy UDPSessionServer interface.
type UDPServer struct {
	block        cipher.Block
	cipherConfig *CipherConfig
	shouldPad    PaddingPolicy
	uPSKMap      map[[IdentityHeaderLength]byte]*CipherConfig

	// Initialized as the same main cipher config referenced by cipherConfig.
	// Produced by NewSession as the current session's user cipher config.
	// Consumed by a follow-up call to NewPacker.
	currentUserCipherConfig *CipherConfig
}

func NewUDPServer(cipherConfig *CipherConfig, shouldPad PaddingPolicy, uPSKMap map[[IdentityHeaderLength]byte]*CipherConfig) *UDPServer {
	return &UDPServer{
		block:                   cipherConfig.NewBlock(),
		cipherConfig:            cipherConfig,
		shouldPad:               shouldPad,
		uPSKMap:                 uPSKMap,
		currentUserCipherConfig: cipherConfig,
	}
}

// FrontHeadroom implements the zerocopy.UDPSessionServer FrontHeadroom method.
func (s *UDPServer) FrontHeadroom() int {
	var identityHeaderLen int
	if len(s.uPSKMap) > 0 {
		identityHeaderLen = IdentityHeaderLength
	}
	return UDPSeparateHeaderLength + identityHeaderLen + UDPClientMessageHeaderMaxLength
}

// RearHeadroom implements the zerocopy.UDPSessionServer RearHeadroom method.
func (s *UDPServer) RearHeadroom() int {
	return 16
}

// SessionInfo implements the zerocopy.UDPSessionServer SessionInfo method.
func (s *UDPServer) SessionInfo(b []byte) (csid uint64, err error) {
	if len(b) < UDPSeparateHeaderLength {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
		return
	}

	s.block.Decrypt(b, b)

	csid = binary.BigEndian.Uint64(b)
	return
}

// NewUnpacker implements the zerocopy.UDPSessionServer NewUnpacker method.
func (s *UDPServer) NewUnpacker(b []byte, csid uint64) (zerocopy.ServerUnpacker, error) {
	var identityHeaderLen int
	hasEIH := len(s.uPSKMap) > 0
	if hasEIH {
		identityHeaderLen = IdentityHeaderLength
	}

	if len(b) < UDPSeparateHeaderLength+identityHeaderLen {
		return nil, fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
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

// NewPacker implements the zerocopy.UDPSessionServer NewPacker method.
func (s *UDPServer) NewPacker(csid uint64) (zerocopy.ServerPacker, error) {
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
		block:     s.currentUserCipherConfig.NewBlock(),
		shouldPad: s.shouldPad,
	}, nil
}

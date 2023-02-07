package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net/netip"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	ShadowPacketClientMessageHeadroom
	addrPort      netip.AddrPort
	name          string
	maxPacketSize int
	fwmark        int
	cipherConfig  *ClientCipherConfig
	shouldPad     PaddingPolicy
}

func NewUDPClient(addrPort netip.AddrPort, name string, mtu, fwmark int, cipherConfig *ClientCipherConfig, shouldPad PaddingPolicy) *UDPClient {
	return &UDPClient{
		ShadowPacketClientMessageHeadroom: ShadowPacketClientMessageHeadroom{IdentityHeaderLength * len(cipherConfig.iPSKs)},
		addrPort:                          addrPort,
		name:                              name,
		maxPacketSize:                     zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr()),
		fwmark:                            fwmark,
		cipherConfig:                      cipherConfig,
		shouldPad:                         shouldPad,
	}
}

// String implements the zerocopy.UDPClient String method.
func (c *UDPClient) String() string {
	return c.name
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
	aead, err := c.cipherConfig.AEAD(salt)
	if err != nil {
		return nil, nil, err
	}

	return &ShadowPacketClientPacker{
			ShadowPacketClientMessageHeadroom: c.ShadowPacketClientMessageHeadroom,
			csid:                              csid,
			aead:                              aead,
			block:                             c.cipherConfig.UDPSeparateHeaderPackerCipher(),
			rng:                               mrand.New(mrand.NewSource(int64(csid))),
			shouldPad:                         c.shouldPad,
			eihCiphers:                        c.cipherConfig.UDPIdentityHeaderCiphers(),
			eihPSKHashes:                      c.cipherConfig.EIHPSKHashes(),
			maxPacketSize:                     c.maxPacketSize,
			serverAddrPort:                    c.addrPort,
		}, &ShadowPacketClientUnpacker{
			csid:         csid,
			cipherConfig: c.cipherConfig,
		}, nil
}

// LinkInfo implements the UDPClient LinkInfo method.
func (c *UDPClient) LinkInfo() (int, int) {
	return c.maxPacketSize, c.fwmark
}

// UDPServer implements the zerocopy UDPSessionServer interface.
type UDPServer struct {
	CredStore
	ShadowPacketClientMessageHeadroom
	block                cipher.Block
	identityCipherConfig ServerIdentityCipherConfig
	shouldPad            PaddingPolicy

	// Initialized as the same primary cipher config.
	// Produced by NewSession as the current session's user cipher config.
	// Consumed by a follow-up call to NewPacker.
	currentUserCipherConfig UserCipherConfig
}

func NewUDPServer(userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, shouldPad PaddingPolicy) *UDPServer {
	var identityHeaderLen int
	block := userCipherConfig.Block()
	if block == nil {
		identityHeaderLen = IdentityHeaderLength
		block = identityCipherConfig.UDP()
	}

	return &UDPServer{
		ShadowPacketClientMessageHeadroom: ShadowPacketClientMessageHeadroom{identityHeaderLen},
		block:                             block,
		identityCipherConfig:              identityCipherConfig,
		shouldPad:                         shouldPad,
		currentUserCipherConfig:           userCipherConfig,
	}
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
	identityHeaderLen := s.ShadowPacketClientMessageHeadroom.identityHeadersLen

	if len(b) < UDPSeparateHeaderLength+identityHeaderLen {
		return nil, fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
	}

	// Process identity header.
	if identityHeaderLen != 0 {
		separateHeader := b[:UDPSeparateHeaderLength]
		identityHeader := b[UDPSeparateHeaderLength : UDPSeparateHeaderLength+identityHeaderLen]
		s.block.Decrypt(identityHeader, identityHeader)
		subtle.XORBytes(identityHeader, identityHeader, separateHeader)
		uPSKHash := *(*[IdentityHeaderLength]byte)(identityHeader)
		userCipherConfig, ok := s.uPSKMap[uPSKHash]
		if !ok {
			return nil, ErrIdentityHeaderUserPSKNotFound
		}
		s.currentUserCipherConfig = userCipherConfig.UserCipherConfig
	}

	aead, err := s.currentUserCipherConfig.AEAD(b[:8])
	if err != nil {
		return nil, err
	}

	return &ShadowPacketServerUnpacker{
		ShadowPacketClientMessageHeadroom: s.ShadowPacketClientMessageHeadroom,
		csid:                              csid,
		aead:                              aead,
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

	aead, err := s.currentUserCipherConfig.AEAD(salt)
	if err != nil {
		return nil, err
	}

	return &ShadowPacketServerPacker{
		ssid:      ssid,
		csid:      csid,
		aead:      aead,
		block:     s.currentUserCipherConfig.Block(),
		rng:       mrand.New(mrand.NewSource(int64(ssid))),
		shouldPad: s.shouldPad,
	}, nil
}

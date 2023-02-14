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
	userCipherConfig     UserCipherConfig
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
		userCipherConfig:                  userCipherConfig,
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
func (s *UDPServer) NewUnpacker(b []byte, csid uint64) (zerocopy.SessionServerUnpacker, string, error) {
	identityHeaderLen := s.ShadowPacketClientMessageHeadroom.identityHeadersLen

	if len(b) < UDPSeparateHeaderLength+identityHeaderLen {
		return nil, "", fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
	}

	userCipherConfig := s.userCipherConfig
	var username string

	// Process identity header.
	if identityHeaderLen != 0 {
		separateHeader := b[:UDPSeparateHeaderLength]
		identityHeader := b[UDPSeparateHeaderLength : UDPSeparateHeaderLength+identityHeaderLen]
		s.block.Decrypt(identityHeader, identityHeader)
		subtle.XORBytes(identityHeader, identityHeader, separateHeader)
		uPSKHash := *(*[IdentityHeaderLength]byte)(identityHeader)
		serverUserCipherConfig := s.ulm[uPSKHash]
		if serverUserCipherConfig == nil {
			return nil, "", ErrIdentityHeaderUserPSKNotFound
		}
		userCipherConfig = serverUserCipherConfig.UserCipherConfig
		username = serverUserCipherConfig.Name
	}

	aead, err := userCipherConfig.AEAD(b[:8])
	if err != nil {
		return nil, "", err
	}

	return &ShadowPacketServerUnpacker{
		ShadowPacketClientMessageHeadroom: s.ShadowPacketClientMessageHeadroom,
		csid:                              csid,
		aead:                              aead,
		userCipherConfig:                  userCipherConfig,
		packerShouldPad:                   s.shouldPad,
	}, username, nil
}

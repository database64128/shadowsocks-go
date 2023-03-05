package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
)

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	addrPort         netip.AddrPort
	info             zerocopy.UDPClientInfo
	nonAEADHeaderLen int
	cipherConfig     *ClientCipherConfig
	shouldPad        PaddingPolicy
}

func NewUDPClient(addrPort netip.AddrPort, name string, mtu int, listenConfig tfo.ListenConfig, cipherConfig *ClientCipherConfig, shouldPad PaddingPolicy) *UDPClient {
	identityHeadersLen := IdentityHeaderLength * len(cipherConfig.iPSKs)
	return &UDPClient{
		addrPort: addrPort,
		info: zerocopy.UDPClientInfo{
			Name:           name,
			PackerHeadroom: ShadowPacketClientMessageHeadroom(identityHeadersLen),
			MaxPacketSize:  zerocopy.MaxPacketSizeForAddr(mtu, addrPort.Addr()),
			ListenConfig:   listenConfig,
		},
		nonAEADHeaderLen: UDPSeparateHeaderLength + identityHeadersLen,
		cipherConfig:     cipherConfig,
		shouldPad:        shouldPad,
	}
}

// Info implements the zerocopy.UDPClient Info method.
func (c *UDPClient) Info() zerocopy.UDPClientInfo {
	return c.info
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *UDPClient) NewSession() (zerocopy.UDPClientInfo, zerocopy.ClientPacker, zerocopy.ClientUnpacker, error) {
	// Random client session ID.
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return c.info, nil, nil, err
	}
	csid := binary.BigEndian.Uint64(salt)
	aead, err := c.cipherConfig.AEAD(salt)
	if err != nil {
		return c.info, nil, nil, err
	}

	return c.info, &ShadowPacketClientPacker{
			csid:             csid,
			aead:             aead,
			block:            c.cipherConfig.UDPSeparateHeaderPackerCipher(),
			shouldPad:        c.shouldPad,
			eihCiphers:       c.cipherConfig.UDPIdentityHeaderCiphers(),
			eihPSKHashes:     c.cipherConfig.EIHPSKHashes(),
			maxPacketSize:    c.info.MaxPacketSize,
			nonAEADHeaderLen: c.nonAEADHeaderLen,
			info: zerocopy.ClientPackerInfo{
				Headroom: c.info.PackerHeadroom,
			},
			serverAddrPort: c.addrPort,
		}, &ShadowPacketClientUnpacker{
			csid:         csid,
			cipherConfig: c.cipherConfig,
		}, nil
}

// UDPServer implements the zerocopy UDPSessionServer interface.
type UDPServer struct {
	CredStore
	info                 zerocopy.UDPSessionServerInfo
	identityHeaderLen    int
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
		info: zerocopy.UDPSessionServerInfo{
			UnpackerHeadroom: ShadowPacketClientMessageHeadroom(identityHeaderLen),
		},
		identityHeaderLen:    identityHeaderLen,
		block:                block,
		identityCipherConfig: identityCipherConfig,
		shouldPad:            shouldPad,
		userCipherConfig:     userCipherConfig,
	}
}

// Info implements the zerocopy.UDPSessionServer Info method.
func (s *UDPServer) Info() zerocopy.UDPSessionServerInfo {
	return s.info
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
	nonAEADHeaderLen := UDPSeparateHeaderLength + s.identityHeaderLen

	if len(b) < nonAEADHeaderLen {
		return nil, "", fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
	}

	userCipherConfig := s.userCipherConfig
	var username string

	// Process identity header.
	if s.identityHeaderLen != 0 {
		separateHeader := b[:UDPSeparateHeaderLength]
		identityHeader := b[UDPSeparateHeaderLength:nonAEADHeaderLen]
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
		csid:             csid,
		aead:             aead,
		nonAEADHeaderLen: nonAEADHeaderLen,
		info: zerocopy.ServerUnpackerInfo{
			Headroom: s.info.UnpackerHeadroom,
		},
		userCipherConfig: userCipherConfig,
		packerShouldPad:  s.shouldPad,
	}, username, nil
}

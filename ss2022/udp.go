package ss2022

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// UDPClient implements the zerocopy UDPClient interface.
type UDPClient struct {
	addr             conn.Addr
	info             zerocopy.UDPClientInfo
	nonAEADHeaderLen int
	filterSize       uint64
	cipherConfig     *ClientCipherConfig
	shouldPad        PaddingPolicy
}

func NewUDPClient(addr conn.Addr, name string, mtu int, listenConfig conn.ListenConfig, filterSize uint64, cipherConfig *ClientCipherConfig, shouldPad PaddingPolicy) *UDPClient {
	identityHeadersLen := IdentityHeaderLength * len(cipherConfig.iPSKs)
	return &UDPClient{
		addr: addr,
		info: zerocopy.UDPClientInfo{
			Name:           name,
			PackerHeadroom: ShadowPacketClientMessageHeadroom(identityHeadersLen),
			MTU:            mtu,
			ListenConfig:   listenConfig,
		},
		nonAEADHeaderLen: UDPSeparateHeaderLength + identityHeadersLen,
		filterSize:       filterSize,
		cipherConfig:     cipherConfig,
		shouldPad:        shouldPad,
	}
}

// Info implements the zerocopy.UDPClient Info method.
func (c *UDPClient) Info() zerocopy.UDPClientInfo {
	return c.info
}

// NewSession implements the zerocopy.UDPClient NewSession method.
func (c *UDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientInfo, zerocopy.UDPClientSession, error) {
	addrPort, err := c.addr.ResolveIPPort(ctx)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to resolve endpoint address: %w", err)
	}
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(c.info.MTU, addrPort.Addr())

	salt := make([]byte, 8)
	if _, err = rand.Read(salt); err != nil {
		return c.info, zerocopy.UDPClientSession{}, err
	}
	csid := binary.BigEndian.Uint64(salt)
	aead, err := c.cipherConfig.AEAD(salt)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, err
	}

	return c.info, zerocopy.UDPClientSession{
		MaxPacketSize: maxPacketSize,
		Packer: &ShadowPacketClientPacker{
			csid:             csid,
			aead:             aead,
			block:            c.cipherConfig.UDPSeparateHeaderPackerCipher(),
			shouldPad:        c.shouldPad,
			eihCiphers:       c.cipherConfig.UDPIdentityHeaderCiphers(),
			eihPSKHashes:     c.cipherConfig.EIHPSKHashes(),
			maxPacketSize:    maxPacketSize,
			nonAEADHeaderLen: c.nonAEADHeaderLen,
			info: zerocopy.ClientPackerInfo{
				Headroom: c.info.PackerHeadroom,
			},
			serverAddrPort: addrPort,
		},
		Unpacker: &ShadowPacketClientUnpacker{
			csid:         csid,
			filterSize:   c.filterSize,
			cipherConfig: c.cipherConfig,
		},
		Close: zerocopy.NoopClose,
	}, nil
}

// UDPServer implements the zerocopy UDPSessionServer interface.
type UDPServer struct {
	CredStore
	info                 zerocopy.UDPSessionServerInfo
	filterSize           uint64
	identityHeaderLen    int
	block                cipher.Block
	identityCipherConfig ServerIdentityCipherConfig
	shouldPad            PaddingPolicy
	userCipherConfig     UserCipherConfig
}

func NewUDPServer(filterSize uint64, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, shouldPad PaddingPolicy) *UDPServer {
	var identityHeaderLen int
	block := userCipherConfig.Block()
	if block == nil {
		identityHeaderLen = IdentityHeaderLength
		block = identityCipherConfig.UDP()
	}

	return &UDPServer{
		info: zerocopy.UDPSessionServerInfo{
			UnpackerHeadroom: ShadowPacketClientMessageHeadroom(identityHeaderLen),
			MinNATTimeout:    ReplayWindowDuration,
		},
		filterSize:           filterSize,
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
func (s *UDPServer) NewUnpacker(b []byte, csid uint64) (zerocopy.ServerUnpacker, string, error) {
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
		filterSize:       s.filterSize,
		nonAEADHeaderLen: nonAEADHeaderLen,
		info: zerocopy.ServerUnpackerInfo{
			Headroom: s.info.UnpackerHeadroom,
		},
		userCipherConfig: userCipherConfig,
		packerShouldPad:  s.shouldPad,
	}, username, nil
}

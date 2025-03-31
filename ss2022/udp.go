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

// UDPClient is a Shadowsocks 2022 UDP client.
//
// UDPClient implements [zerocopy.UDPClient].
type UDPClient struct {
	network          string
	addr             conn.Addr
	info             zerocopy.UDPClientSessionInfo
	nonAEADHeaderLen int
	filterSize       uint64
	cipherConfig     *ClientCipherConfig
	shouldPad        PaddingPolicy
}

// NewUDPClient creates a new Shadowsocks 2022 UDP client.
func NewUDPClient(name, network string, addr conn.Addr, mtu int, listenConfig conn.ListenConfig, filterSize uint64, cipherConfig *ClientCipherConfig, shouldPad PaddingPolicy) *UDPClient {
	identityHeadersLen := IdentityHeaderLength * len(cipherConfig.iPSKs)

	return &UDPClient{
		network: network,
		addr:    addr,
		info: zerocopy.UDPClientSessionInfo{
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

// Info implements [zerocopy.UDPClient.Info].
func (c *UDPClient) Info() zerocopy.UDPClientInfo {
	return zerocopy.UDPClientInfo{
		Name:           c.info.Name,
		PackerHeadroom: c.info.PackerHeadroom,
	}
}

// NewSession implements [zerocopy.UDPClient.NewSession].
func (c *UDPClient) NewSession(ctx context.Context) (zerocopy.UDPClientSessionInfo, zerocopy.UDPClientSession, error) {
	addrPort, err := c.addr.ResolveIPPort(ctx, c.network)
	if err != nil {
		return c.info, zerocopy.UDPClientSession{}, fmt.Errorf("failed to resolve endpoint address: %w", err)
	}
	maxPacketSize := zerocopy.MaxPacketSizeForAddr(c.info.MTU, addrPort.Addr())

	salt := make([]byte, 8)
	rand.Read(salt)
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

// UDPServer is a Shadowsocks 2022 UDP server.
//
// UDPServer implements [zerocopy.UDPSessionServer].
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

// NewUDPServer creates a new Shadowsocks 2022 UDP server.
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

// Info implements [zerocopy.UDPSessionServer.Info].
func (s *UDPServer) Info() zerocopy.UDPSessionServerInfo {
	return s.info
}

// SessionInfo implements [zerocopy.UDPSessionServer.SessionInfo].
func (s *UDPServer) SessionInfo(b []byte) (csid uint64, err error) {
	if len(b) < UDPSeparateHeaderLength {
		err = fmt.Errorf("%w: %d", zerocopy.ErrPacketTooSmall, len(b))
		return
	}

	s.block.Decrypt(b, b)

	csid = binary.BigEndian.Uint64(b)
	return
}

// NewUnpacker implements [zerocopy.UDPSessionServer.NewUnpacker].
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
		serverUserCipherConfig, ok := s.CredStore.LookupUser(uPSKHash)
		if !ok {
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

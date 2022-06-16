package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"

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

func NewUDPClient(cipherConfig *CipherConfig, shouldPad func(socks5.Addr) bool) *UDPClient {
	return &UDPClient{
		block:        cipherConfig.NewBlock(),
		cipherConfig: cipherConfig,
		shouldPad:    shouldPad,
		eihCiphers:   cipherConfig.NewUDPIdentityHeaderClientCiphers(),
		eihPSKHashes: cipherConfig.ClientPSKHashes(),
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

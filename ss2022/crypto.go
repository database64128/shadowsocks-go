package ss2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

var (
	ErrUnknownMethod = errors.New("unknown method")
	ErrBadPSKLength  = errors.New("PSK length does not meet method requirements")
)

type CipherConfig struct {
	// Client: uPSK
	// Server: iPSK or uPSK
	PSK []byte

	// Client: iPSKs
	// Server: uPSKs
	PSKs [][]byte
}

func NewCipherConfig(method string, psk []byte, psks [][]byte) (*CipherConfig, error) {
	var pskLength int
	switch method {
	case "2022-blake3-aes-128-gcm":
		pskLength = 16
	case "2022-blake3-aes-256-gcm":
		pskLength = 32
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownMethod, method)
	}

	if len(psk) != pskLength {
		return nil, fmt.Errorf("%w: %s", ErrBadPSKLength, base64.StdEncoding.EncodeToString(psk))
	}

	for _, psk := range psks {
		if len(psk) != pskLength {
			return nil, fmt.Errorf("%w: %s", ErrBadPSKLength, base64.StdEncoding.EncodeToString(psk))
		}
	}

	return &CipherConfig{psk, psks}, nil
}

func NewRandomCipherConfig(method string, keySize, eihCount int) (cipherConfig *CipherConfig, err error) {
	psk := make([]byte, keySize)
	_, err = rand.Read(psk)
	if err != nil {
		return
	}

	psks := make([][]byte, eihCount)
	for i := range psks {
		psks[i] = make([]byte, keySize)
		_, err = rand.Read(psks[i])
		if err != nil {
			return
		}
	}

	cipherConfig, err = NewCipherConfig(method, psk, psks)
	return
}

func (c *CipherConfig) NewAEAD(salt []byte) cipher.AEAD {
	var key []byte

	if len(salt) > 0 {
		keyMaterial := make([]byte, len(c.PSK)+len(salt))
		copy(keyMaterial, c.PSK)
		copy(keyMaterial[len(c.PSK):], salt)
		key = make([]byte, len(c.PSK))
		blake3.DeriveKey(key, "shadowsocks 2022 session subkey", keyMaterial)
	} else {
		key = c.PSK
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return aead
}

func (c *CipherConfig) NewShadowStreamCipher(salt []byte) *ShadowStreamCipher {
	aead := c.NewAEAD(salt)
	nonce := make([]byte, aead.NonceSize())
	return &ShadowStreamCipher{
		aead:  aead,
		nonce: nonce,
	}
}

func (c *CipherConfig) NewBlock() cipher.Block {
	block, err := aes.NewCipher(c.PSK)
	if err != nil {
		panic(err)
	}
	return block
}

// NewTCPIdentityHeaderClientCiphers creates block ciphers for a client TCP session's identity headers.
func (c *CipherConfig) NewTCPIdentityHeaderClientCiphers(salt []byte) []cipher.Block {
	ciphers := make([]cipher.Block, len(c.PSKs))

	for i := range ciphers {
		keyMaterial := make([]byte, len(c.PSKs[i])+len(salt))
		copy(keyMaterial, c.PSKs[i])
		copy(keyMaterial[len(c.PSKs[i]):], salt)
		key := make([]byte, len(c.PSKs[i]))
		blake3.DeriveKey(key, "shadowsocks 2022 identity subkey", keyMaterial)

		var err error
		ciphers[i], err = aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
	}

	return ciphers
}

// NewTCPIdentityHeaderServerCiphers creates a block cipher for a server TCP session's identity header.
func (c *CipherConfig) NewTCPIdentityHeaderServerCipher(salt []byte) cipher.Block {
	// Skip if no uPSKs.
	if len(c.PSKs) == 0 {
		return nil
	}

	keyMaterial := make([]byte, len(c.PSK)+len(salt))
	copy(keyMaterial, c.PSK)
	copy(keyMaterial[len(c.PSK):], salt)
	key := make([]byte, len(c.PSK))
	blake3.DeriveKey(key, "shadowsocks 2022 identity subkey", keyMaterial)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return block
}

// NewUDPIdentityHeaderClientCiphers creates block ciphers for a client UDP service's identity headers.
func (c *CipherConfig) NewUDPIdentityHeaderClientCiphers() []cipher.Block {
	ciphers := make([]cipher.Block, len(c.PSKs))

	for i := range ciphers {
		var err error
		ciphers[i], err = aes.NewCipher(c.PSKs[i])
		if err != nil {
			panic(err)
		}
	}

	return ciphers
}

// NewUDPIdentityHeaderServerCipher creates a block cipher for a server UDP service's identity header.
func (c *CipherConfig) NewUDPIdentityHeaderServerCipher() cipher.Block {
	// Skip if no uPSKs.
	if len(c.PSKs) == 0 {
		return nil
	}

	return c.NewBlock()
}

// ClientPSKHashes returns the BLAKE3 hashes of c.PSKs[1:] and c.PSK.
func (c *CipherConfig) ClientPSKHashes() [][IdentityHeaderLength]byte {
	// Skip if no uPSKs.
	if len(c.PSKs) == 0 {
		return nil
	}

	hashes := make([][IdentityHeaderLength]byte, len(c.PSKs))

	for i := 1; i < len(c.PSKs); i++ {
		hash := blake3.Sum512(c.PSKs[i])
		copy(hashes[i-1][:], hash[:])
	}

	hash := blake3.Sum512(c.PSK)
	copy(hashes[len(hashes)-1][:], hash[:])

	return hashes
}

// ServerPSKHashMap returns a uPSKHash-*CipherConfig map.
func (c *CipherConfig) ServerPSKHashMap() map[[IdentityHeaderLength]byte]*CipherConfig {
	uPSKMap := make(map[[IdentityHeaderLength]byte]*CipherConfig, len(c.PSKs))

	for _, psk := range c.PSKs {
		hash := blake3.Sum512(psk)
		truncatedHash := *(*[IdentityHeaderLength]byte)(hash[:])
		uPSKMap[truncatedHash] = &CipherConfig{psk, nil}
	}

	return uPSKMap
}

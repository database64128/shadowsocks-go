package ss2022

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

const (
	subkeyCtxSession  = "shadowsocks 2022 session subkey"
	subkeyCtxIdentity = "shadowsocks 2022 identity subkey"
)

func deriveSubkey(key, psk, salt []byte, ctx string) {
	keyMaterial := make([]byte, 0, 32+32) // allocate on the stack
	keyMaterial = append(keyMaterial, psk...)
	keyMaterial = append(keyMaterial, salt...)
	blake3.DeriveKey(key, ctx, keyMaterial)
}

func newAES(psk, salt []byte, ctx string) (cipher.Block, error) {
	if len(psk) == 0 || len(salt) == 0 {
		return nil, errors.New("empty psk or salt")
	}
	key := make([]byte, len(psk), 32) // allocate on the stack
	deriveSubkey(key, psk, salt, ctx)
	return aes.NewCipher(key)
}

func newAESGCM(psk, salt []byte) (cipher.AEAD, error) {
	block, err := newAES(psk, salt, subkeyCtxSession)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// UserCipherConfig stores cipher configuration for a non-EIH client/server or an EIH user.
type UserCipherConfig struct {
	PSK   []byte
	block cipher.Block
}

// NewUserCipherConfig returns a new UserCipherConfig.
func NewUserCipherConfig(psk []byte, enableUDP bool) (c UserCipherConfig, err error) {
	c.PSK = psk
	if enableUDP {
		c.block, err = aes.NewCipher(psk)
	}
	return
}

// AEAD derives a subkey from the salt and returns a new AEAD cipher.
func (c UserCipherConfig) AEAD(salt []byte) (cipher.AEAD, error) {
	return newAESGCM(c.PSK, salt)
}

func (c UserCipherConfig) ShadowStreamCipher(salt []byte) (*ShadowStreamCipher, error) {
	aead, err := c.AEAD(salt)
	if err != nil {
		return nil, err
	}
	return NewShadowStreamCipher(aead), nil
}

// Block returns the block cipher for UDP separate header.
func (c UserCipherConfig) Block() cipher.Block {
	return c.block
}

// ClientCipherConfig stores cipher configuration for a client.
type ClientCipherConfig struct {
	UserCipherConfig
	iPSKs        [][]byte
	eihCiphers   []cipher.Block
	eihPSKHashes [][IdentityHeaderLength]byte
}

// TCPIdentityHeaderCiphers creates block ciphers for a client TCP session's identity headers.
func (c *ClientCipherConfig) TCPIdentityHeaderCiphers(salt []byte) ([]cipher.Block, error) {
	ciphers := make([]cipher.Block, len(c.iPSKs))

	for i := range ciphers {
		var err error
		ciphers[i], err = newAES(c.iPSKs[i], salt, subkeyCtxIdentity)
		if err != nil {
			return nil, err
		}
	}

	return ciphers, nil
}

// UDPIdentityHeaderCiphers returns the block ciphers for a client UDP service's identity headers.
func (c *ClientCipherConfig) UDPIdentityHeaderCiphers() []cipher.Block {
	return c.eihCiphers
}

// EIHPSKHashes returns the truncated BLAKE3 hashes of c.iPSKs[1:] and c.PSK.
func (c *ClientCipherConfig) EIHPSKHashes() [][IdentityHeaderLength]byte {
	return c.eihPSKHashes
}

// UDPSeparateHeaderPackerCipher returns the block cipher used by the client packer to encrypt the separate header.
func (c *ClientCipherConfig) UDPSeparateHeaderPackerCipher() cipher.Block {
	if len(c.eihCiphers) > 0 {
		return c.eihCiphers[0]
	}
	return c.block
}

func udpIdentityHeaderClientCiphers(iPSKs [][]byte) ([]cipher.Block, error) {
	ciphers := make([]cipher.Block, len(iPSKs))

	for i := range ciphers {
		var err error
		ciphers[i], err = aes.NewCipher(iPSKs[i])
		if err != nil {
			return nil, err
		}
	}

	return ciphers, nil
}

func clientPSKHashes(iPSKs [][]byte, psk []byte) [][IdentityHeaderLength]byte {
	if len(iPSKs) == 0 {
		return nil
	}

	hashes := make([][IdentityHeaderLength]byte, len(iPSKs))

	for i := 1; i < len(iPSKs); i++ {
		hash := blake3.Sum512(iPSKs[i])
		hashes[i-1] = [IdentityHeaderLength]byte(hash[:])
	}

	hash := blake3.Sum512(psk)
	hashes[len(hashes)-1] = [IdentityHeaderLength]byte(hash[:])

	return hashes
}

// NewClientCipherConfig returns a new ClientCipherConfig.
func NewClientCipherConfig(psk []byte, iPSKs [][]byte, enableUDP bool) (c *ClientCipherConfig, err error) {
	c = &ClientCipherConfig{
		UserCipherConfig: UserCipherConfig{
			PSK: psk,
		},
		iPSKs:        iPSKs,
		eihPSKHashes: clientPSKHashes(iPSKs, psk),
	}
	if enableUDP {
		c.block, err = aes.NewCipher(psk)
		if err != nil {
			return
		}
		c.eihCiphers, err = udpIdentityHeaderClientCiphers(iPSKs)
	}
	return
}

// ServerIdentityCipherConfig stores cipher configuration for a server's identity header.
type ServerIdentityCipherConfig struct {
	IPSK  []byte
	block cipher.Block
}

// NewServerIdentityCipherConfig returns a new ServerIdentityCipherConfig.
func NewServerIdentityCipherConfig(iPSK []byte, enableUDP bool) (c ServerIdentityCipherConfig, err error) {
	c.IPSK = iPSK
	if enableUDP {
		c.block, err = aes.NewCipher(iPSK)
	}
	return
}

// TCP creates a block cipher for a server TCP session's identity header.
func (c ServerIdentityCipherConfig) TCP(salt []byte) (cipher.Block, error) {
	return newAES(c.IPSK, salt, subkeyCtxIdentity)
}

// UDP returns the block cipher for a server UDP service's identity header.
func (c ServerIdentityCipherConfig) UDP() cipher.Block {
	return c.block
}

// ServerUserCipherConfig stores cipher configuration for a server's EIH user.
type ServerUserCipherConfig struct {
	UserCipherConfig
	Name string
}

// NewServerUserCipherConfig returns a new ServerUserCipherConfig.
func NewServerUserCipherConfig(name string, psk []byte, enableUDP bool) (c *ServerUserCipherConfig, err error) {
	c = &ServerUserCipherConfig{Name: name}
	c.UserCipherConfig, err = NewUserCipherConfig(psk, enableUDP)
	return
}

// PSKHash returns the given PSK's BLAKE3 hash truncated to [IdentityHeaderLength] bytes.
func PSKHash(psk []byte) [IdentityHeaderLength]byte {
	hash := blake3.Sum512(psk)
	return [IdentityHeaderLength]byte(hash[:])
}

// PSKLengthForMethod returns the required length of the PSK for the given method.
func PSKLengthForMethod(method string) (int, error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm":
		return 32, nil
	default:
		return 0, fmt.Errorf("unknown method: %s", method)
	}
}

type PSKLengthError struct {
	PSK            []byte
	ExpectedLength int
}

func (e PSKLengthError) Error() string {
	return fmt.Sprintf("expected PSK length %d, got %d from %s", e.ExpectedLength, len(e.PSK), base64.StdEncoding.EncodeToString(e.PSK))
}

// CheckPSKLength checks that the PSK is the correct length for the given method.
func CheckPSKLength(method string, psk []byte, psks [][]byte) error {
	pskLength, err := PSKLengthForMethod(method)
	if err != nil {
		return err
	}

	if len(psk) != pskLength {
		return &PSKLengthError{psk, pskLength}
	}

	for _, psk := range psks {
		if len(psk) != pskLength {
			return &PSKLengthError{psk, pskLength}
		}
	}

	return nil
}

// UserLookupMap is a map of uPSK hashes to [*ServerUserCipherConfig].
// Upon decryption of an identity header, the uPSK hash is looked up in this map.
type UserLookupMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig

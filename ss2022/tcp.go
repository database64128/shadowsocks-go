package ss2022

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"sync"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	name                       string
	rwo                        zerocopy.DirectReadWriteCloserOpener
	cipherConfig               *CipherConfig
	eihPSKHashes               [][IdentityHeaderLength]byte
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

func NewTCPClient(name, address string, dialerTFO bool, dialerFwmark int, cipherConfig *CipherConfig, eihPSKHashes [][IdentityHeaderLength]byte, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) *TCPClient {
	return &TCPClient{
		name:                       name,
		rwo:                        zerocopy.NewTCPConnOpener(conn.NewDialer(dialerTFO, dialerFwmark), "tcp", address),
		cipherConfig:               cipherConfig,
		eihPSKHashes:               eihPSKHashes,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
}

// String implements the zerocopy.TCPClient String method.
func (c *TCPClient) String() string {
	return c.name
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
	var (
		paddingPayloadLen int
		excessPayload     []byte
	)

	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	payloadLen := len(payload)
	roomForPayload := MaxPayloadSize - targetAddrLen - 2

	switch {
	case payloadLen > roomForPayload:
		paddingPayloadLen = roomForPayload
		excessPayload = payload[roomForPayload:]
		payload = payload[:roomForPayload]
	case payloadLen >= MaxPaddingLength:
		paddingPayloadLen = payloadLen
	case payloadLen > 0:
		paddingPayloadLen = payloadLen + mrand.Intn(MaxPaddingLength-payloadLen+1)
	default:
		paddingPayloadLen = 1 + mrand.Intn(MaxPaddingLength)
	}

	urspLen := len(c.unsafeRequestStreamPrefix)
	saltLen := len(c.cipherConfig.PSK)
	identityHeadersLen := IdentityHeaderLength * len(c.eihPSKHashes)
	identityHeadersStart := urspLen + saltLen
	fixedLengthHeaderStart := identityHeadersStart + identityHeadersLen
	fixedLengthHeaderEnd := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength
	variableLengthHeaderStart := fixedLengthHeaderEnd + 16
	variableLengthHeaderLen := targetAddrLen + 2 + paddingPayloadLen
	variableLengthHeaderEnd := variableLengthHeaderStart + variableLengthHeaderLen
	bufferLen := variableLengthHeaderEnd + 16
	b := make([]byte, bufferLen)
	ursp := b[:urspLen]
	salt := b[urspLen:identityHeadersStart]
	identityHeaders := b[identityHeadersStart:fixedLengthHeaderStart]
	fixedLengthHeaderPlaintext := b[fixedLengthHeaderStart:fixedLengthHeaderEnd]
	variableLengthHeaderPlaintext := b[variableLengthHeaderStart:variableLengthHeaderEnd]

	// Write unsafe request stream prefix.
	copy(ursp, c.unsafeRequestStreamPrefix)

	// Random salt.
	_, err = rand.Read(salt)
	if err != nil {
		return
	}

	// Write and encrypt identity headers.
	eihCiphers := c.cipherConfig.NewTCPIdentityHeaderClientCiphers(salt)

	for i := range c.eihPSKHashes {
		identityHeader := identityHeaders[i*IdentityHeaderLength : (i+1)*IdentityHeaderLength]
		eihCiphers[i].Encrypt(identityHeader, c.eihPSKHashes[i][:])
	}

	// Write variable-length header.
	WriteTCPRequestVariableLengthHeader(variableLengthHeaderPlaintext, targetAddr, payload)

	// Write fixed-length header.
	WriteTCPRequestFixedLengthHeader(fixedLengthHeaderPlaintext, uint16(variableLengthHeaderLen))

	// Create AEAD cipher.
	shadowStreamCipher := c.cipherConfig.NewShadowStreamCipher(salt)

	// Seal fixed-length header.
	shadowStreamCipher.EncryptInPlace(fixedLengthHeaderPlaintext)

	// Seal variable-length header.
	shadowStreamCipher.EncryptInPlace(variableLengthHeaderPlaintext)

	// Write out.
	rawRW, err = c.rwo.Open(b)
	if err != nil {
		return
	}

	w := ShadowStreamWriter{
		writer: rawRW,
		ssc:    shadowStreamCipher,
	}

	// Write excess payload, reusing the variable-length header buffer.
	for len(excessPayload) > 0 {
		n := copy(variableLengthHeaderPlaintext, excessPayload)
		excessPayload = excessPayload[n:]
		if _, err = w.WriteZeroCopy(b, variableLengthHeaderStart, n); err != nil {
			rawRW.Close()
			return
		}
	}

	rw = &ShadowStreamClientReadWriter{
		w:                          &w,
		rawRW:                      rawRW,
		cipherConfig:               c.cipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: c.unsafeResponseStreamPrefix,
	}

	return
}

// NativeInitialPayload implements the zerocopy.TCPClient NativeInitialPayload method.
func (c *TCPClient) NativeInitialPayload() bool {
	return true
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	mu                         sync.Mutex
	cipherConfig               *CipherConfig
	saltPool                   *SaltPool[string]
	uPSKMap                    map[[IdentityHeaderLength]byte]*CipherConfig
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

func NewTCPServer(cipherConfig *CipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*CipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) *TCPServer {
	return &TCPServer{
		cipherConfig:               cipherConfig,
		saltPool:                   NewSaltPool[string](ReplayWindowDuration),
		uPSKMap:                    uPSKMap,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	var identityHeaderLen int
	if len(s.uPSKMap) > 0 {
		identityHeaderLen = IdentityHeaderLength
	}

	urspLen := len(s.unsafeRequestStreamPrefix)
	saltLen := len(s.cipherConfig.PSK)
	identityHeaderStart := urspLen + saltLen
	fixedLengthHeaderStart := identityHeaderStart + identityHeaderLen
	bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + 16
	b := make([]byte, bufferLen)

	// Read unsafe request stream prefix, salt, identity header, fixed-length header.
	n, err := rawRW.Read(b)
	if err != nil {
		return
	}
	if n < bufferLen {
		payload = b[:n]
		err = &HeaderError[int]{ErrFirstRead, bufferLen, n}
		return
	}

	ursp := b[:urspLen]
	salt := b[urspLen:identityHeaderStart]
	ciphertext := b[fixedLengthHeaderStart:]

	s.mu.Lock()

	// Check but not add request salt to pool.
	if !s.saltPool.Check(string(salt)) { // Is the compiler smart enough to not incur an allocation here?
		s.mu.Unlock()
		payload = b[:n]
		err = ErrRepeatedSalt
		return
	}

	// Check unsafe request stream prefix.
	if !bytes.Equal(ursp, s.unsafeRequestStreamPrefix) {
		s.mu.Unlock()
		payload = b[:n]
		err = &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, s.unsafeRequestStreamPrefix, ursp}
		return
	}

	// Process identity header.
	if identityHeaderLen != 0 {
		var uPSKHash [IdentityHeaderLength]byte
		identityHeader := b[identityHeaderStart:fixedLengthHeaderStart]
		identityHeaderCipher := s.cipherConfig.NewTCPIdentityHeaderServerCipher(salt)
		identityHeaderCipher.Decrypt(uPSKHash[:], identityHeader)

		userCipherConfig, ok := s.uPSKMap[uPSKHash]
		if !ok {
			s.mu.Unlock()
			payload = b[:n]
			err = ErrIdentityHeaderUserPSKNotFound
			return
		}
		s.cipherConfig = userCipherConfig
	}

	// Derive key and create cipher.
	shadowStreamCipher := s.cipherConfig.NewShadowStreamCipher(salt)

	// AEAD open.
	plaintext, err := shadowStreamCipher.DecryptTo(nil, ciphertext)
	if err != nil {
		s.mu.Unlock()
		payload = b[:n]
		return
	}

	// Parse fixed-length header.
	vhlen, err := ParseTCPRequestFixedLengthHeader(plaintext)
	if err != nil {
		s.mu.Unlock()
		return
	}

	// Add request salt to pool.
	s.saltPool.Add(string(salt))

	s.mu.Unlock()

	b = make([]byte, vhlen+16)

	// Read variable-length header.
	_, err = io.ReadFull(rawRW, b)
	if err != nil {
		return
	}

	// AEAD open.
	plaintext, err = shadowStreamCipher.DecryptInPlace(b)
	if err != nil {
		return
	}

	// Parse variable-length header.
	targetAddr, payload, err = ParseTCPRequestVariableLengthHeader(plaintext)
	if err != nil {
		return
	}

	r := ShadowStreamReader{
		reader: rawRW,
		ssc:    shadowStreamCipher,
	}
	rw = &ShadowStreamServerReadWriter{
		r:                          &r,
		rawRW:                      rawRW,
		cipherConfig:               s.cipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: s.unsafeResponseStreamPrefix,
	}
	return
}

// NativeInitialPayload implements the zerocopy.TCPServer NativeInitialPayload method.
func (s *TCPServer) NativeInitialPayload() bool {
	return true
}

// DefaultTCPConnCloser implements the zerocopy.TCPServer DefaultTCPConnCloser method.
func (s *TCPServer) DefaultTCPConnCloser() zerocopy.TCPConnCloser {
	return zerocopy.ForceReset
}

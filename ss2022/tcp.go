package ss2022

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/fastrand"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// TCPClient implements the zerocopy TCPClient interface.
type TCPClient struct {
	name                       string
	rwo                        zerocopy.DirectReadWriteCloserOpener
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	cipherConfig               *ClientCipherConfig
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

func NewTCPClient(name, address string, dialer conn.Dialer, allowSegmentedFixedLengthHeader bool, cipherConfig *ClientCipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) *TCPClient {
	return &TCPClient{
		name:                       name,
		rwo:                        zerocopy.NewTCPConnOpener(dialer, "tcp", address),
		readOnceOrFull:             readOnceOrFullFunc(allowSegmentedFixedLengthHeader),
		cipherConfig:               cipherConfig,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
}

// Info implements the zerocopy.TCPClient Info method.
func (c *TCPClient) Info() zerocopy.TCPClientInfo {
	return zerocopy.TCPClientInfo{
		Name:                 c.name,
		NativeInitialPayload: true,
	}
}

// Dial implements the zerocopy.TCPClient Dial method.
func (c *TCPClient) Dial(ctx context.Context, targetAddr conn.Addr, payload []byte) (rawRW zerocopy.DirectReadWriteCloser, rw zerocopy.ReadWriter, err error) {
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
		paddingPayloadLen = payloadLen + int(fastrand.Uint32n(MaxPaddingLength-uint32(payloadLen)+1))
	default:
		paddingPayloadLen = 1 + int(fastrand.Uint32n(MaxPaddingLength))
	}

	urspLen := len(c.unsafeRequestStreamPrefix)
	saltLen := len(c.cipherConfig.PSK)
	eihPSKHashes := c.cipherConfig.EIHPSKHashes()
	identityHeadersLen := IdentityHeaderLength * len(eihPSKHashes)
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
	eihCiphers, err := c.cipherConfig.TCPIdentityHeaderCiphers(salt)
	if err != nil {
		return
	}

	for i := range eihPSKHashes {
		identityHeader := identityHeaders[i*IdentityHeaderLength : (i+1)*IdentityHeaderLength]
		eihCiphers[i].Encrypt(identityHeader, eihPSKHashes[i][:])
	}

	// Write variable-length header.
	WriteTCPRequestVariableLengthHeader(variableLengthHeaderPlaintext, targetAddr, payload)

	// Write fixed-length header.
	WriteTCPRequestFixedLengthHeader(fixedLengthHeaderPlaintext, uint16(variableLengthHeaderLen))

	// Create AEAD cipher.
	shadowStreamCipher, err := c.cipherConfig.ShadowStreamCipher(salt)
	if err != nil {
		return
	}

	// Seal fixed-length header.
	shadowStreamCipher.EncryptInPlace(fixedLengthHeaderPlaintext)

	// Seal variable-length header.
	shadowStreamCipher.EncryptInPlace(variableLengthHeaderPlaintext)

	// Write out.
	rawRW, err = c.rwo.Open(ctx, b)
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
		ShadowStreamWriter:         &w,
		rawRW:                      rawRW,
		readOnceOrFull:             c.readOnceOrFull,
		cipherConfig:               c.cipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: c.unsafeResponseStreamPrefix,
	}

	return
}

// TCPServer implements the zerocopy TCPServer interface.
type TCPServer struct {
	CredStore
	saltPool                   *SaltPool[string]
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	userCipherConfig           UserCipherConfig
	identityCipherConfig       ServerIdentityCipherConfig
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

func NewTCPServer(allowSegmentedFixedLengthHeader bool, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) *TCPServer {
	return &TCPServer{
		saltPool:                   NewSaltPool[string](ReplayWindowDuration),
		readOnceOrFull:             readOnceOrFullFunc(allowSegmentedFixedLengthHeader),
		userCipherConfig:           userCipherConfig,
		identityCipherConfig:       identityCipherConfig,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
}

// Info implements the zerocopy.TCPServer Info method.
func (s *TCPServer) Info() zerocopy.TCPServerInfo {
	return zerocopy.TCPServerInfo{
		NativeInitialPayload: true,
		DefaultTCPConnCloser: zerocopy.ForceReset,
	}
}

// Accept implements the zerocopy.TCPServer Accept method.
func (s *TCPServer) Accept(rawRW zerocopy.DirectReadWriteCloser) (rw zerocopy.ReadWriter, targetAddr conn.Addr, payload []byte, username string, err error) {
	var identityHeaderLen int
	userCipherConfig := s.userCipherConfig
	saltLen := len(userCipherConfig.PSK)
	if saltLen == 0 {
		saltLen = len(s.identityCipherConfig.IPSK)
		identityHeaderLen = IdentityHeaderLength
	}

	urspLen := len(s.unsafeRequestStreamPrefix)
	identityHeaderStart := urspLen + saltLen
	fixedLengthHeaderStart := identityHeaderStart + identityHeaderLen
	bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + 16
	b := make([]byte, bufferLen)

	// Read unsafe request stream prefix, salt, identity header, fixed-length header.
	n, err := s.readOnceOrFull(rawRW, b)
	if err != nil {
		payload = b[:n]
		return
	}

	ursp := b[:urspLen]
	salt := b[urspLen:identityHeaderStart]
	ciphertext := b[fixedLengthHeaderStart:]

	s.Lock()

	// Check but not add request salt to pool.
	if !s.saltPool.Check(string(salt)) { // Is the compiler smart enough to not incur an allocation here?
		s.Unlock()
		payload = b[:n]
		err = ErrRepeatedSalt
		return
	}

	// Check unsafe request stream prefix.
	if !bytes.Equal(ursp, s.unsafeRequestStreamPrefix) {
		s.Unlock()
		payload = b[:n]
		err = &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, s.unsafeRequestStreamPrefix, ursp}
		return
	}

	// Process identity header.
	if identityHeaderLen != 0 {
		var identityHeaderCipher cipher.Block
		identityHeaderCipher, err = s.identityCipherConfig.TCP(salt)
		if err != nil {
			s.Unlock()
			return
		}

		var uPSKHash [IdentityHeaderLength]byte
		identityHeader := b[identityHeaderStart:fixedLengthHeaderStart]
		identityHeaderCipher.Decrypt(uPSKHash[:], identityHeader)

		serverUserCipherConfig := s.ulm[uPSKHash]
		if serverUserCipherConfig == nil {
			s.Unlock()
			payload = b[:n]
			err = ErrIdentityHeaderUserPSKNotFound
			return
		}
		userCipherConfig = serverUserCipherConfig.UserCipherConfig
		username = serverUserCipherConfig.Name
	}

	// Derive key and create cipher.
	shadowStreamCipher, err := userCipherConfig.ShadowStreamCipher(salt)
	if err != nil {
		s.Unlock()
		return
	}

	// AEAD open.
	plaintext, err := shadowStreamCipher.DecryptTo(nil, ciphertext)
	if err != nil {
		s.Unlock()
		payload = b[:n]
		return
	}

	// Parse fixed-length header.
	vhlen, err := ParseTCPRequestFixedLengthHeader(plaintext)
	if err != nil {
		s.Unlock()
		return
	}

	// Add request salt to pool.
	s.saltPool.Add(string(salt))

	s.Unlock()

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
		ShadowStreamReader:         &r,
		rawRW:                      rawRW,
		cipherConfig:               userCipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: s.unsafeResponseStreamPrefix,
	}
	return
}

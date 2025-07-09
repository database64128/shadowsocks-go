package ss2022

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"net"
	"slices"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/socks5"
	"go.uber.org/zap"
)

// StreamClientConfig is the configuration for a Shadowsocks 2022 stream client.
type StreamClientConfig struct {
	// Name is the name of the client.
	Name string

	// InnerClient is the underlying stream client.
	InnerClient netio.StreamClient

	// Addr is the address of the Shadowsocks 2022 server.
	Addr conn.Addr

	// AllowSegmentedFixedLengthHeader controls whether to allow segmented fixed-length header.
	//
	// Setting it to true disables the requirement that the fixed-length header must be read in
	// a single read call. This is useful when the underlying stream transport does not exhibit
	// typical TCP behavior.
	AllowSegmentedFixedLengthHeader bool

	// CipherConfig is the cipher configuration.
	CipherConfig *ClientCipherConfig

	// UnsafeRequestStreamPrefix is the prefix bytes prepended to the request stream.
	UnsafeRequestStreamPrefix []byte

	// UnsafeResponseStreamPrefix is the prefix bytes prepended to the response stream.
	UnsafeResponseStreamPrefix []byte
}

// NewStreamClient returns a new Shadowsocks 2022 stream client.
func (c *StreamClientConfig) NewStreamClient() *StreamClient {
	return &StreamClient{
		name:                       c.Name,
		innerClient:                c.InnerClient,
		serverAddr:                 c.Addr,
		readOnceOrFull:             readOnceOrFullFunc(c.AllowSegmentedFixedLengthHeader),
		cipherConfig:               c.CipherConfig,
		unsafeRequestStreamPrefix:  c.UnsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: c.UnsafeResponseStreamPrefix,
	}
}

// StreamClient is a Shadowsocks 2022 stream client.
//
// StreamClient implements [netio.StreamClient] and [netio.StreamDialer].
type StreamClient struct {
	name                       string
	innerClient                netio.StreamClient
	serverAddr                 conn.Addr
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	cipherConfig               *ClientCipherConfig
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

var (
	_ netio.StreamClient = (*StreamClient)(nil)
	_ netio.StreamDialer = (*StreamClient)(nil)
)

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (c *StreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, netio.StreamDialerInfo{
		Name:                 c.name,
		NativeInitialPayload: true,
	}
}

// DialStream implements [netio.StreamDialer.DialStream].
func (c *StreamClient) DialStream(ctx context.Context, targetAddr conn.Addr, payload []byte) (clientConn netio.Conn, err error) {
	var (
		paddingPayloadLen int
		excessPayload     []byte
	)

	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	payloadLen := len(payload)
	roomForPayload := streamMaxPayloadSize - targetAddrLen - 2

	switch {
	case payloadLen > roomForPayload:
		paddingPayloadLen = roomForPayload
		excessPayload = payload[roomForPayload:]
		payload = payload[:roomForPayload]
	case payloadLen >= MaxPaddingLength:
		paddingPayloadLen = payloadLen
	case payloadLen > 0:
		paddingPayloadLen = payloadLen + mrand.IntN(MaxPaddingLength-payloadLen+1)
	default:
		paddingPayloadLen = 1 + mrand.IntN(MaxPaddingLength)
	}

	urspLen := len(c.unsafeRequestStreamPrefix)
	saltLen := len(c.cipherConfig.PSK)
	eihPSKHashes := c.cipherConfig.EIHPSKHashes()
	identityHeadersLen := IdentityHeaderLength * len(eihPSKHashes)
	identityHeadersStart := urspLen + saltLen
	fixedLengthHeaderStart := identityHeadersStart + identityHeadersLen
	fixedLengthHeaderEnd := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength
	variableLengthHeaderStart := fixedLengthHeaderEnd + tagSize
	variableLengthHeaderLen := targetAddrLen + 2 + paddingPayloadLen
	variableLengthHeaderEnd := variableLengthHeaderStart + variableLengthHeaderLen
	bufferLen := variableLengthHeaderEnd + tagSize

	writeBuf := getWriteBuf()
	var b []byte
	if bufferLen <= cap(writeBuf) {
		b = writeBuf[:bufferLen]
	} else {
		b = make([]byte, bufferLen)
	}

	ursp := b[:urspLen]
	salt := b[urspLen:identityHeadersStart]
	identityHeaders := b[identityHeadersStart:fixedLengthHeaderStart]
	fixedLengthHeaderPlaintext := b[fixedLengthHeaderStart:fixedLengthHeaderEnd]
	variableLengthHeaderPlaintext := b[variableLengthHeaderStart:variableLengthHeaderEnd]

	// Write unsafe request stream prefix.
	copy(ursp, c.unsafeRequestStreamPrefix)

	// Random salt.
	rand.Read(salt)

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
	PutTCPRequestVariableLengthHeader(variableLengthHeaderPlaintext, targetAddr, payload)

	// Write fixed-length header.
	PutTCPRequestFixedLengthHeader(fixedLengthHeaderPlaintext, time.Now(), variableLengthHeaderLen)

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
	innerConn, err := c.innerClient.DialStream(ctx, c.serverAddr, b)
	if err != nil {
		return
	}

	clientConn = &ShadowStreamClientConn{
		ShadowStreamConn: ShadowStreamConn{
			Conn:        innerConn,
			writeBuf:    writeBuf,
			writeCipher: shadowStreamCipher,
		},
		readOnceOrFull:             c.readOnceOrFull,
		unsafeResponseStreamPrefix: c.unsafeResponseStreamPrefix,
		cipherConfig:               c.cipherConfig,
		requestSalt:                lengthExtendSalt(salt),
		requestSaltLen:             saltLen,
	}

	// Write excess payload.
	if len(excessPayload) > 0 {
		if _, err = netio.ConnWriteContext(ctx, clientConn, excessPayload); err != nil {
			_ = clientConn.Close()
			return nil, err
		}
	}

	return
}

// StreamServerConfig is the configuration for a Shadowsocks 2022 stream server.
type StreamServerConfig struct {
	// AllowSegmentedFixedLengthHeader controls whether to allow segmented fixed-length header.
	//
	// Setting it to true disables the requirement that the fixed-length header must be read in
	// a single read call. This is useful when the underlying stream transport does not exhibit
	// typical TCP behavior.
	AllowSegmentedFixedLengthHeader bool

	// UserCipherConfig is the non-EIH cipher configuration.
	UserCipherConfig UserCipherConfig

	// IdentityCipherConfig is the cipher configuration for the identity header.
	IdentityCipherConfig ServerIdentityCipherConfig

	// RejectPolicy takes care of incoming connections that cannot be authenticated.
	RejectPolicy RejectPolicy

	// UnsafeFallbackAddr is the optional fallback destination address for unauthenticated connections.
	UnsafeFallbackAddr conn.Addr

	// UnsafeRequestStreamPrefix is the prefix bytes prepended to the request stream.
	UnsafeRequestStreamPrefix []byte

	// UnsafeResponseStreamPrefix is the prefix bytes prepended to the response stream.
	UnsafeResponseStreamPrefix []byte
}

// NewStreamServer returns a new Shadowsocks 2022 stream server.
func (c *StreamServerConfig) NewStreamServer() *StreamServer {
	return &StreamServer{
		saltPool:                   *NewSaltPool(),
		readOnceOrFull:             readOnceOrFullFunc(c.AllowSegmentedFixedLengthHeader),
		userCipherConfig:           c.UserCipherConfig,
		identityCipherConfig:       c.IdentityCipherConfig,
		rejectPolicy:               c.RejectPolicy,
		unsafeFallbackAddr:         c.UnsafeFallbackAddr,
		unsafeRequestStreamPrefix:  c.UnsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: c.UnsafeResponseStreamPrefix,
	}
}

// StreamServer is a Shadowsocks 2022 stream server.
//
// StreamServer implements [netio.StreamServer].
type StreamServer struct {
	CredStore
	saltPool                   SaltPool
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	userCipherConfig           UserCipherConfig
	identityCipherConfig       ServerIdentityCipherConfig
	rejectPolicy               RejectPolicy
	unsafeFallbackAddr         conn.Addr
	unsafeRequestStreamPrefix  []byte
	unsafeResponseStreamPrefix []byte
}

var _ netio.StreamServer = (*StreamServer)(nil)

// StreamServerInfo implements [netio.StreamServer.StreamServerInfo].
func (s *StreamServer) StreamServerInfo() netio.StreamServerInfo {
	return netio.StreamServerInfo{
		NativeInitialPayload: true,
	}
}

// HandleStream implements [netio.StreamServer.HandleStream].
func (s *StreamServer) HandleStream(rawRW netio.Conn, logger *zap.Logger) (req netio.ConnRequest, err error) {
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
	// We want fallback to reliably work before we can authenticate the connection.
	// That means all decryption work must not happen in-place.
	// Reserve 16 bytes at the end for decrypted identity and fixed-length headers.
	reservedStart := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + tagSize
	bufferLen := reservedStart + IdentityHeaderLength

	// Even though we are performing a read here, we still prefer the write buffer,
	// because it's larger, and the type-asserted writeTo path only ever uses the
	// write buffer.
	writeBuf := getWriteBuf()
	var b []byte
	if bufferLen <= cap(writeBuf) {
		b = writeBuf[:bufferLen]
	} else {
		b = make([]byte, bufferLen)
	}
	readBuf := b[:reservedStart]

	var n int
	defer func() {
		if err != nil {
			if n > 0 && s.unsafeFallbackAddr.IsValid() {
				logger.Warn("Initiating fallback for unauthenticated connection", zap.Error(err))
				req = netio.ConnRequest{
					PendingConn: netio.NopPendingConn(rawRW),
					Addr:        s.unsafeFallbackAddr,
					Payload:     readBuf[:n],
				}
				err = nil
				return
			}

			if tc, ok := rawRW.(*net.TCPConn); ok {
				s.rejectPolicy(tc, logger)
			}
		}
	}()

	// Read unsafe request stream prefix, salt, identity header, fixed-length header.
	n, err = s.readOnceOrFull(rawRW, readBuf)
	if err != nil {
		return
	}

	ursp := b[:urspLen]
	salt := b[urspLen:identityHeaderStart]
	ciphertext := b[fixedLengthHeaderStart:reservedStart]
	reserved := b[reservedStart:]
	extendedSalt := lengthExtendSalt(salt)

	// Check but not add request salt to pool.
	if s.saltPool.TryContains(extendedSalt) {
		err = ErrRepeatedSalt
		return
	}

	// Check unsafe request stream prefix.
	if !bytes.Equal(ursp, s.unsafeRequestStreamPrefix) {
		err = &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, s.unsafeRequestStreamPrefix, ursp}
		return
	}

	// Process identity header.
	if identityHeaderLen != 0 {
		var identityHeaderCipher cipher.Block
		identityHeaderCipher, err = s.identityCipherConfig.TCP(salt)
		if err != nil {
			return
		}

		identityHeader := b[identityHeaderStart:fixedLengthHeaderStart]
		identityHeaderCipher.Decrypt(reserved, identityHeader)

		serverUserCipherConfig, ok := s.CredStore.LookupUser([IdentityHeaderLength]byte(reserved))
		if !ok {
			err = ErrIdentityHeaderUserPSKNotFound
			return
		}
		userCipherConfig = serverUserCipherConfig.UserCipherConfig
		req.Username = serverUserCipherConfig.Name
	}

	// Derive key and create cipher.
	shadowStreamCipher, err := userCipherConfig.ShadowStreamCipher(salt)
	if err != nil {
		return
	}

	// AEAD open.
	plaintext, err := shadowStreamCipher.DecryptTo(reserved, ciphertext)
	if err != nil {
		return
	}

	now := time.Now()

	// Parse fixed-length header.
	vhlen, err := ParseTCPRequestFixedLengthHeader(plaintext, now)
	if err != nil {
		return
	}

	// Add request salt to pool.
	if !s.saltPool.Add(now, extendedSalt) {
		return req, ErrRepeatedSalt
	}

	// Connection is authenticated. Fallback is no longer an option.
	n = 0

	bufferLen = vhlen + tagSize
	if bufferLen <= cap(writeBuf) {
		b = writeBuf[:bufferLen]
	} else {
		b = make([]byte, bufferLen)
	}

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
	req.Addr, req.Payload, err = ParseTCPRequestVariableLengthHeader(plaintext)
	if err != nil {
		return
	}

	req.PendingConn = netio.NopPendingConn(&ShadowStreamServerConn{
		ShadowStreamConn: ShadowStreamConn{
			Conn:       rawRW,
			readCipher: shadowStreamCipher,
			writeBuf:   writeBuf,
		},
		unsafeResponseStreamPrefix: s.unsafeResponseStreamPrefix,
		cipherConfig:               userCipherConfig,
		requestSalt:                extendedSalt,
		requestSaltLen:             saltLen,
	})
	return
}

func getWriteBuf() (b []byte) {
	return slices.Grow(b, streamWriteBufferSize)
}

func lengthExtendSalt(salt []byte) (out [32]byte) {
	_ = copy(out[:], salt)
	return out
}

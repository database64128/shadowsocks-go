package ss2022

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand"

	"github.com/database64128/shadowsocks-go/conn"
	_ "github.com/database64128/shadowsocks-go/mrandseed"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

const MaxPayloadSize = 0xFFFF

var (
	ErrZeroLengthChunk = errors.New("length in length chunk is zero")
	ErrFirstRead       = errors.New("failed to read fixed-length header in one read call")
	ErrRepeatedSalt    = errors.New("detected replay: repeated salt")
)

var ErrUnsafeStreamPrefixMismatch = errors.New("unsafe stream prefix mismatch")

// ShadowStreamServerReadWriter implements Shadowsocks stream server.
type ShadowStreamServerReadWriter struct {
	r                          *ShadowStreamReader
	w                          *ShadowStreamWriter
	rawRW                      zerocopy.DirectReadWriteCloser
	cipherConfig               *CipherConfig
	requestSalt                []byte
	unsafeResponseStreamPrefix []byte
}

// NewShadowStreamServerReadWriter reads the request headers from rw to establish a session.
func NewShadowStreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, cipherConfig *CipherConfig, saltPool *SaltPool[string], uPSKMap map[[IdentityHeaderLength]byte]*CipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) (sssRW *ShadowStreamServerReadWriter, targetAddr conn.Addr, payload []byte, err error) {
	var identityHeaderLen int
	if len(uPSKMap) > 0 {
		identityHeaderLen = IdentityHeaderLength
	}

	urspLen := len(unsafeRequestStreamPrefix)
	saltLen := len(cipherConfig.PSK)
	identityHeaderStart := urspLen + saltLen
	fixedLengthHeaderStart := identityHeaderStart + identityHeaderLen
	bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + 16
	b := make([]byte, bufferLen)

	// Read unsafe request stream prefix, salt, identity header, fixed-length header.
	n, err := rw.Read(b)
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

	// Check unsafe request stream prefix.
	if !bytes.Equal(ursp, unsafeRequestStreamPrefix) {
		payload = b[:n]
		err = &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, unsafeRequestStreamPrefix, ursp}
		return
	}

	// Process identity header.
	if identityHeaderLen != 0 {
		var uPSKHash [IdentityHeaderLength]byte
		identityHeader := b[identityHeaderStart:fixedLengthHeaderStart]
		identityHeaderCipher := cipherConfig.NewTCPIdentityHeaderServerCipher(salt)
		identityHeaderCipher.Decrypt(uPSKHash[:], identityHeader)

		userCipherConfig, ok := uPSKMap[uPSKHash]
		if !ok {
			payload = b[:n]
			err = ErrIdentityHeaderUserPSKNotFound
			return
		}
		cipherConfig = userCipherConfig
	}

	// Derive key and create cipher.
	shadowStreamCipher := cipherConfig.NewShadowStreamCipher(salt)

	// AEAD open.
	plaintext, err := shadowStreamCipher.DecryptTo(nil, ciphertext)
	if err != nil {
		payload = b[:n]
		return
	}

	// Parse fixed-length header.
	vhlen, err := ParseTCPRequestFixedLengthHeader(plaintext)
	if err != nil {
		return
	}

	// Check request salt.
	if !saltPool.Add(string(salt)) {
		err = ErrRepeatedSalt
		return
	}

	b = make([]byte, vhlen+16)

	// Read variable-length header.
	_, err = io.ReadFull(rw, b)
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
		reader: rw,
		ssc:    shadowStreamCipher,
	}
	sssRW = &ShadowStreamServerReadWriter{
		r:                          &r,
		rawRW:                      rw,
		cipherConfig:               cipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
	return
}

// FrontHeadroom implements the Writer FrontHeadroom method.
func (rw *ShadowStreamServerReadWriter) FrontHeadroom() int {
	return rw.r.FrontHeadroom()
}

// RearHeadroom implements the Writer RearHeadroom method.
func (rw *ShadowStreamServerReadWriter) RearHeadroom() int {
	return rw.r.RearHeadroom()
}

// MaxPayloadSizePerWrite implements the Writer MaxPayloadSizePerWrite method.
func (rw *ShadowStreamServerReadWriter) MaxPayloadSizePerWrite() int {
	return rw.r.MinPayloadBufferSizePerRead()
}

// MinPayloadBufferSizePerRead implements the Reader MinPayloadBufferSizePerRead method.
func (rw *ShadowStreamServerReadWriter) MinPayloadBufferSizePerRead() int {
	return rw.r.MinPayloadBufferSizePerRead()
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (rw *ShadowStreamServerReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (int, error) {
	if rw.w == nil { // first write
		urspLen := len(rw.unsafeResponseStreamPrefix)
		saltLen := len(rw.cipherConfig.PSK)
		responseHeaderStart := urspLen + saltLen
		responseHeaderEnd := responseHeaderStart + TCPRequestFixedLengthHeaderLength + saltLen
		payloadBufStart := responseHeaderEnd + 16
		bufferLen := payloadBufStart + payloadLen + 16
		hb := make([]byte, bufferLen)
		ursp := hb[:urspLen]
		salt := hb[urspLen:responseHeaderStart]
		responseHeader := hb[responseHeaderStart:responseHeaderEnd]

		// Write unsafe response stream prefix.
		copy(ursp, rw.unsafeResponseStreamPrefix)

		// Random salt.
		_, err := rand.Read(salt)
		if err != nil {
			return 0, err
		}

		// Write response header.
		WriteTCPResponseHeader(responseHeader, rw.requestSalt, uint16(payloadLen))

		// Create AEAD cipher.
		shadowStreamCipher := rw.cipherConfig.NewShadowStreamCipher(salt)

		// Create writer.
		rw.w = &ShadowStreamWriter{
			writer: rw.rawRW,
			ssc:    shadowStreamCipher,
		}

		// Seal response header.
		shadowStreamCipher.EncryptInPlace(responseHeader)

		// Seal payload.
		dst := hb[payloadBufStart:]
		plaintext := b[payloadStart : payloadStart+payloadLen]
		shadowStreamCipher.EncryptTo(dst, plaintext)

		// Write out.
		_, err = rw.rawRW.Write(hb)
		if err != nil {
			return 0, err
		}

		return payloadLen, nil
	}

	return rw.w.WriteZeroCopy(b, payloadStart, payloadLen)
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (rw *ShadowStreamServerReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (int, error) {
	return rw.r.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

// CloseRead implements the ReadWriter CloseRead method.
func (rw *ShadowStreamServerReadWriter) CloseRead() error {
	return rw.rawRW.CloseRead()
}

// CloseWrite implements the ReadWriter CloseWrite method.
func (rw *ShadowStreamServerReadWriter) CloseWrite() error {
	return rw.rawRW.CloseWrite()
}

// Close implements the ReadWriter Close method.
func (rw *ShadowStreamServerReadWriter) Close() error {
	return rw.rawRW.Close()
}

// ShadowStreamClientReadWriter implements Shadowsocks stream client.
type ShadowStreamClientReadWriter struct {
	r                          *ShadowStreamReader
	w                          *ShadowStreamWriter
	rawRW                      zerocopy.DirectReadWriteCloser
	cipherConfig               *CipherConfig
	requestSalt                []byte
	unsafeResponseStreamPrefix []byte
}

// NewShadowStreamClientReadWriter writes request headers to rw and returns a Shadowsocks stream client ready for reads and writes.
func NewShadowStreamClientReadWriter(rwo zerocopy.DirectReadWriteCloserOpener, cipherConfig *CipherConfig, eihPSKHashes [][IdentityHeaderLength]byte, targetAddr conn.Addr, payload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) (sscRW *ShadowStreamClientReadWriter, rawRW zerocopy.DirectReadWriteCloser, err error) {
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

	urspLen := len(unsafeRequestStreamPrefix)
	saltLen := len(cipherConfig.PSK)
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
	copy(ursp, unsafeRequestStreamPrefix)

	// Random salt.
	_, err = rand.Read(salt)
	if err != nil {
		return
	}

	// Write and encrypt identity headers.
	eihCiphers := cipherConfig.NewTCPIdentityHeaderClientCiphers(salt)

	for i := range eihPSKHashes {
		identityHeader := identityHeaders[i*IdentityHeaderLength : (i+1)*IdentityHeaderLength]
		eihCiphers[i].Encrypt(identityHeader, eihPSKHashes[i][:])
	}

	// Write variable-length header.
	WriteTCPRequestVariableLengthHeader(variableLengthHeaderPlaintext, targetAddr, payload)

	// Write fixed-length header.
	WriteTCPRequestFixedLengthHeader(fixedLengthHeaderPlaintext, uint16(variableLengthHeaderLen))

	// Create AEAD cipher.
	shadowStreamCipher := cipherConfig.NewShadowStreamCipher(salt)

	// Seal fixed-length header.
	shadowStreamCipher.EncryptInPlace(fixedLengthHeaderPlaintext)

	// Seal variable-length header.
	shadowStreamCipher.EncryptInPlace(variableLengthHeaderPlaintext)

	// Write out.
	rawRW, err = rwo.Open(b)
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

	sscRW = &ShadowStreamClientReadWriter{
		w:                          &w,
		rawRW:                      rawRW,
		cipherConfig:               cipherConfig,
		requestSalt:                salt,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}

	return
}

// FrontHeadroom implements the Writer FrontHeadroom method.
func (rw *ShadowStreamClientReadWriter) FrontHeadroom() int {
	return rw.w.FrontHeadroom()
}

// RearHeadroom implements the Writer RearHeadroom method.
func (rw *ShadowStreamClientReadWriter) RearHeadroom() int {
	return rw.w.RearHeadroom()
}

// MaxPayloadSizePerWrite implements the Writer MaxPayloadSizePerWrite method.
func (rw *ShadowStreamClientReadWriter) MaxPayloadSizePerWrite() int {
	return rw.w.MaxPayloadSizePerWrite()
}

// MinPayloadBufferSizePerRead implements the Reader MinPayloadBufferSizePerRead method.
func (rw *ShadowStreamClientReadWriter) MinPayloadBufferSizePerRead() int {
	return rw.w.MaxPayloadSizePerWrite()
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (rw *ShadowStreamClientReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (int, error) {
	return rw.w.WriteZeroCopy(b, payloadStart, payloadLen)
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (rw *ShadowStreamClientReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (int, error) {
	if rw.r == nil { // first read
		urspLen := len(rw.unsafeResponseStreamPrefix)
		saltLen := len(rw.cipherConfig.PSK)
		fixedLengthHeaderStart := urspLen + saltLen
		bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + saltLen + 16
		hb := make([]byte, bufferLen)

		// Read response header.
		n, err := rw.rawRW.Read(hb)
		if err != nil {
			return 0, err
		}
		if n < bufferLen {
			return 0, &HeaderError[int]{ErrFirstRead, bufferLen, n}
		}

		// Check unsafe response stream prefix.
		ursp := hb[:urspLen]
		if !bytes.Equal(ursp, rw.unsafeResponseStreamPrefix) {
			return 0, &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, rw.unsafeResponseStreamPrefix, ursp}
		}

		// Derive key and create cipher.
		salt := hb[urspLen:fixedLengthHeaderStart]
		ciphertext := hb[fixedLengthHeaderStart:]
		shadowStreamCipher := rw.cipherConfig.NewShadowStreamCipher(salt)

		// Create reader.
		rw.r = &ShadowStreamReader{
			reader: rw.rawRW,
			ssc:    shadowStreamCipher,
		}

		// AEAD open.
		plaintext, err := shadowStreamCipher.DecryptInPlace(ciphertext)
		if err != nil {
			return 0, err
		}

		// Parse response header.
		n, err = ParseTCPResponseHeader(plaintext, rw.requestSalt)
		if err != nil {
			return 0, err
		}

		payloadBuf := b[payloadBufStart : payloadBufStart+n+16]

		// Read payload chunk.
		_, err = io.ReadFull(rw.rawRW, payloadBuf)
		if err != nil {
			return 0, err
		}

		// AEAD open.
		_, err = shadowStreamCipher.DecryptInPlace(payloadBuf)
		if err != nil {
			return 0, err
		}

		return n, nil
	}

	return rw.r.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

// CloseRead implements the ReadWriter CloseRead method.
func (rw *ShadowStreamClientReadWriter) CloseRead() error {
	return rw.rawRW.CloseRead()
}

// CloseWrite implements the ReadWriter CloseWrite method.
func (rw *ShadowStreamClientReadWriter) CloseWrite() error {
	return rw.rawRW.CloseWrite()
}

// Close implements the ReadWriter Close method.
func (rw *ShadowStreamClientReadWriter) Close() error {
	return rw.rawRW.Close()
}

// ShadowStreamWriter wraps an io.WriteCloser and feeds an encrypted Shadowsocks stream to it.
//
// Wire format:
//
//	+------------------------+---------------------------+
//	| encrypted length chunk |  encrypted payload chunk  |
//	+------------------------+---------------------------+
//	|  2B length + 16B tag   | variable length + 16B tag |
//	+------------------------+---------------------------+
type ShadowStreamWriter struct {
	writer io.WriteCloser
	ssc    *ShadowStreamCipher
}

// FrontHeadroom implements the Writer FrontHeadroom method.
func (w *ShadowStreamWriter) FrontHeadroom() int {
	return 2 + w.ssc.Overhead()
}

// RearHeadroom implements the Writer RearHeadroom method.
func (w *ShadowStreamWriter) RearHeadroom() int {
	return w.ssc.Overhead()
}

// MaxPayloadSizePerWrite implements the Writer MaxPayloadSizePerWrite method.
func (w *ShadowStreamWriter) MaxPayloadSizePerWrite() int {
	return MaxPayloadSize
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (w *ShadowStreamWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	overhead := w.ssc.Overhead()
	lengthStart := payloadStart - overhead - 2
	lengthBuf := b[lengthStart : lengthStart+2]
	payloadBuf := b[payloadStart : payloadStart+payloadLen]
	payloadTagEnd := payloadStart + payloadLen + overhead
	chunksBuf := b[lengthStart:payloadTagEnd]

	// Write length.
	binary.BigEndian.PutUint16(lengthBuf, uint16(payloadLen))

	// Seal length chunk.
	w.ssc.EncryptInPlace(lengthBuf)

	// Seal payload chunk.
	w.ssc.EncryptInPlace(payloadBuf)

	// Write to wrapped writer.
	_, err = w.writer.Write(chunksBuf)
	if err != nil {
		return
	}
	payloadWritten = payloadLen
	return
}

// Close implements the Writer Close method.
func (w *ShadowStreamWriter) Close() error {
	return w.writer.Close()
}

// ShadowStreamReader wraps an io.ReadCloser and reads from it as an encrypted Shadowsocks stream.
type ShadowStreamReader struct {
	reader io.ReadCloser
	ssc    *ShadowStreamCipher
}

// FrontHeadroom implements the Reader FrontHeadroom method.
func (r *ShadowStreamReader) FrontHeadroom() int {
	return 2 + r.ssc.Overhead()
}

// RearHeadroom implements the Reader RearHeadroom method.
func (r *ShadowStreamReader) RearHeadroom() int {
	return r.ssc.Overhead()
}

// MinPayloadBufferSizePerRead implements the Reader MinPayloadBufferSizePerRead method.
func (r *ShadowStreamReader) MinPayloadBufferSizePerRead() int {
	return MaxPayloadSize
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (r *ShadowStreamReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	overhead := r.ssc.Overhead()
	sealedLengthChunkStart := payloadBufStart - overhead - 2
	sealedLengthChunkBuf := b[sealedLengthChunkStart:payloadBufStart]

	// Read sealed length chunk.
	_, err = io.ReadFull(r.reader, sealedLengthChunkBuf)
	if err != nil {
		return
	}

	// Open sealed length chunk.
	_, err = r.ssc.DecryptInPlace(sealedLengthChunkBuf)
	if err != nil {
		return
	}

	// Validate length.
	payloadLen = int(binary.BigEndian.Uint16(sealedLengthChunkBuf))
	if payloadLen == 0 {
		err = ErrZeroLengthChunk
		return
	}

	// Read sealed payload chunk.
	sealedPayloadChunkBuf := b[payloadBufStart : payloadBufStart+payloadLen+overhead]
	_, err = io.ReadFull(r.reader, sealedPayloadChunkBuf)
	if err != nil {
		payloadLen = 0
		return
	}

	// Open sealed payload chunk.
	_, err = r.ssc.DecryptInPlace(sealedPayloadChunkBuf)
	if err != nil {
		payloadLen = 0
	}

	return
}

// Close implements the Reader Close method.
func (r *ShadowStreamReader) Close() error {
	return r.reader.Close()
}

// ShadowStreamCipher wraps an AEAD cipher and provides methods that transparently increments
// the nonce after each AEAD operation.
type ShadowStreamCipher struct {
	aead  cipher.AEAD
	nonce []byte
}

// Overhead returns the tag size of the AEAD cipher.
func (c *ShadowStreamCipher) Overhead() int {
	return c.aead.Overhead()
}

// EncryptInPlace encrypts and authenticates plaintext in-place.
func (c *ShadowStreamCipher) EncryptInPlace(plaintext []byte) (ciphertext []byte) {
	ciphertext = c.aead.Seal(plaintext[:0], c.nonce, plaintext, nil)
	increment(c.nonce)
	return
}

// EncryptTo encrypts and authenticates the plaintext and saves the ciphertext to dst.
func (c *ShadowStreamCipher) EncryptTo(dst, plaintext []byte) (ciphertext []byte) {
	ciphertext = c.aead.Seal(dst[:0], c.nonce, plaintext, nil)
	increment(c.nonce)
	return
}

// DecryptInplace decrypts and authenticates ciphertext in-place.
func (c *ShadowStreamCipher) DecryptInPlace(ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(ciphertext[:0], c.nonce, ciphertext, nil)
	if err == nil {
		increment(c.nonce)
	}
	return
}

// DecryptTo decrypts and authenticates the ciphertext and saves the plaintext to dst.
func (c *ShadowStreamCipher) DecryptTo(dst, ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(dst[:0], c.nonce, ciphertext, nil)
	if err == nil {
		increment(c.nonce)
	}
	return
}

// increment increments a little-endian unsigned integer b.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

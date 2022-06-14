package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/database64128/shadowsocks-go/socks5"
)

var (
	ErrZeroLengthChunk = errors.New("length in length chunk is zero")
	ErrFirstRead       = errors.New("failed to read fixed-length header in one read call")
)

// ShadowStreamServerReadWriter implements the necessary methods for a Shadowsocks TCP server.
type ShadowStreamServerReadWriter struct {
	r            *ShadowStreamReader
	w            *ShadowStreamWriter
	cipherConfig *CipherConfig
	requestSalt  []byte
}

// NewShadowStreamServerReadWriter reads the request headers from rw to establish a session.
func NewShadowStreamServerReadWriter(rw io.ReadWriter, cipherConfig *CipherConfig) (sssrw *ShadowStreamServerReadWriter, targetAddr socks5.Addr, payload []byte, err error) {
	saltLen := len(cipherConfig.PSK)
	bufferLen := saltLen + TCPRequestFixedLengthHeaderLength + 16
	b := make([]byte, bufferLen)

	// Read fixed-length header.
	n, err := rw.Read(b)
	if err != nil {
		return
	}
	if n < bufferLen {
		err = &HeaderError[int]{ErrFirstRead, bufferLen, n}
		return
	}

	// Derive key and create cipher.
	salt := b[:saltLen]
	ciphertext := b[saltLen:]
	aead := cipherConfig.NewAEAD(salt)
	nonce := make([]byte, aead.NonceSize())
	shadowStreamCipher := ShadowStreamCipher{
		aead:  aead,
		nonce: nonce,
	}

	// AEAD open.
	plaintext, err := shadowStreamCipher.DecryptInPlace(ciphertext)
	if err != nil {
		return
	}

	// Parse fixed-length header.
	vhlen, err := ParseTCPRequestFixedLengthHeader(plaintext)
	if err != nil {
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
		ssc:    &shadowStreamCipher,
	}
	sssrw = &ShadowStreamServerReadWriter{
		r:            &r,
		cipherConfig: cipherConfig,
		requestSalt:  salt,
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

// MaximumPayloadBufferSize implements the Writer MaximumPayloadBufferSize method.
func (rw *ShadowStreamServerReadWriter) MaximumPayloadBufferSize() int {
	return rw.r.MinimumPayloadBufferSize()
}

// MinimumPayloadBufferSize implements the Reader MinimumPayloadBufferSize method.
func (rw *ShadowStreamServerReadWriter) MinimumPayloadBufferSize() int {
	return rw.r.MinimumPayloadBufferSize()
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (rw *ShadowStreamServerReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (int, error) {
	if rw.w == nil { // first write
		saltLen := len(rw.cipherConfig.PSK)
		bufferLen := saltLen + TCPRequestFixedLengthHeaderLength + saltLen + 16 + 2 + 16 + payloadLen + 16
		b := make([]byte, bufferLen)
		salt := b[:saltLen]
		responseHeaderPlaintextEnd := saltLen + TCPRequestFixedLengthHeaderLength + saltLen
		responseHeader := b[saltLen:responseHeaderPlaintextEnd]
		payloadBufStart := responseHeaderPlaintextEnd + 16

		// Random salt.
		_, err := rand.Read(salt)
		if err != nil {
			return 0, err
		}

		// Write response header.
		_ = WriteTCPResponseHeader(responseHeader, rw.requestSalt, uint16(payloadLen))

		// Create AEAD cipher.
		aead := rw.cipherConfig.NewAEAD(salt)
		nonce := make([]byte, aead.NonceSize())
		shadowStreamCipher := ShadowStreamCipher{
			aead:  aead,
			nonce: nonce,
		}

		// Seal response header.
		shadowStreamCipher.EncryptInPlace(responseHeader)

		// Seal payload.
		aead.Seal(b[payloadBufStart:payloadBufStart], nonce, b[payloadStart:payloadStart+payloadLen], nil)
		increment(nonce)

		// Write out.
		w := rw.r.reader.(io.Writer)
		_, err = w.Write(b)
		if err != nil {
			return 0, err
		}

		// Create writer.
		rw.w = &ShadowStreamWriter{
			writer: w,
			ssc:    &shadowStreamCipher,
		}

		return payloadLen, nil
	}

	return rw.w.WriteZeroCopy(b, payloadStart, payloadLen)
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (rw *ShadowStreamServerReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (int, error) {
	return rw.r.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

// ShadowStreamWriter wraps an io.Writer and feeds an encrypted Shadowsocks stream to it.
//
// Wire format:
// 	+------------------------+---------------------------+
// 	| encrypted length chunk |  encrypted payload chunk  |
// 	+------------------------+---------------------------+
// 	|  2B length + 16B tag   | variable length + 16B tag |
// 	+------------------------+---------------------------+
type ShadowStreamWriter struct {
	writer io.Writer
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

// MaximumPayloadBufferSize implements the Writer MaximumPayloadBufferSize method.
func (w *ShadowStreamWriter) MaximumPayloadBufferSize() int {
	return w.FrontHeadroom() + 0xFFFF + w.RearHeadroom()
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

// ShadowStreamReader wraps an io.Reader and reads from it as an encrypted Shadowsocks stream.
type ShadowStreamReader struct {
	reader io.Reader
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

// MinimumPayloadBufferSize implements the Reader MinimumPayloadBufferSize method.
func (r *ShadowStreamReader) MinimumPayloadBufferSize() int {
	return r.FrontHeadroom() + 0xFFFF + r.RearHeadroom()
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

// DecryptInplace decrypts and authenticates ciphertext in-place.
func (c *ShadowStreamCipher) DecryptInPlace(ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(ciphertext[:0], c.nonce, ciphertext, nil)
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

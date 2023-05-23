package ss2022

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

const MaxPayloadSize = 0xFFFF

// ShadowStreamHeadroom is the headroom required by an encrypted Shadowsocks stream.
//
// Front is the size of an encrypted length chunk.
// Rear is the size of an AEAD tag.
var ShadowStreamHeadroom = zerocopy.Headroom{
	Front: 2 + 16,
	Rear:  16,
}

// ShadowStreamReaderInfo contains information about a [ShadowStreamReader].
var ShadowStreamReaderInfo = zerocopy.ReaderInfo{
	Headroom:                    ShadowStreamHeadroom,
	MinPayloadBufferSizePerRead: MaxPayloadSize,
}

// ShadowStreamWriterInfo contains information about a [ShadowStreamWriter].
var ShadowStreamWriterInfo = zerocopy.WriterInfo{
	Headroom:               ShadowStreamHeadroom,
	MaxPayloadSizePerWrite: MaxPayloadSize,
}

var (
	ErrZeroLengthChunk = errors.New("length in length chunk is zero")
	ErrFirstRead       = errors.New("failed to read fixed-length header in one read call")
	ErrRepeatedSalt    = errors.New("detected replay: repeated salt")
)

var ErrUnsafeStreamPrefixMismatch = errors.New("unsafe stream prefix mismatch")

// ShadowStreamServerReadWriter implements Shadowsocks stream server.
type ShadowStreamServerReadWriter struct {
	*ShadowStreamReader
	*ShadowStreamWriter
	rawRW                      zerocopy.DirectReadWriteCloser
	cipherConfig               UserCipherConfig
	requestSalt                []byte
	unsafeResponseStreamPrefix []byte
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (rw *ShadowStreamServerReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (int, error) {
	if rw.ShadowStreamWriter == nil { // first write
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
		shadowStreamCipher, err := rw.cipherConfig.ShadowStreamCipher(salt)
		if err != nil {
			return 0, err
		}

		// Create writer.
		rw.ShadowStreamWriter = &ShadowStreamWriter{
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

	return rw.ShadowStreamWriter.WriteZeroCopy(b, payloadStart, payloadLen)
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
	*ShadowStreamReader
	*ShadowStreamWriter
	rawRW                      zerocopy.DirectReadWriteCloser
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	cipherConfig               *ClientCipherConfig
	requestSalt                []byte
	unsafeResponseStreamPrefix []byte
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (rw *ShadowStreamClientReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (int, error) {
	if rw.ShadowStreamReader == nil { // first read
		urspLen := len(rw.unsafeResponseStreamPrefix)
		saltLen := len(rw.cipherConfig.PSK)
		fixedLengthHeaderStart := urspLen + saltLen
		bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + saltLen + 16
		hb := make([]byte, bufferLen)

		// Read response header.
		n, err := rw.readOnceOrFull(rw.rawRW, hb)
		if err != nil {
			return 0, err
		}

		// Check unsafe response stream prefix.
		ursp := hb[:urspLen]
		if !bytes.Equal(ursp, rw.unsafeResponseStreamPrefix) {
			return 0, &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, rw.unsafeResponseStreamPrefix, ursp}
		}

		// Derive key and create cipher.
		salt := hb[urspLen:fixedLengthHeaderStart]
		ciphertext := hb[fixedLengthHeaderStart:]
		shadowStreamCipher, err := rw.cipherConfig.ShadowStreamCipher(salt)
		if err != nil {
			return 0, err
		}

		// Create reader.
		rw.ShadowStreamReader = &ShadowStreamReader{
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

	return rw.ShadowStreamReader.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
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

// WriterInfo implements the Writer WriterInfo method.
func (w *ShadowStreamWriter) WriterInfo() zerocopy.WriterInfo {
	return ShadowStreamWriterInfo
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

// ShadowStreamReader wraps an io.ReadCloser and reads from it as an encrypted Shadowsocks stream.
type ShadowStreamReader struct {
	reader io.ReadCloser
	ssc    *ShadowStreamCipher
}

// ReaderInfo implements the Reader ReaderInfo method.
func (r *ShadowStreamReader) ReaderInfo() zerocopy.ReaderInfo {
	return ShadowStreamReaderInfo
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

// NewShadowStreamCipher wraps the given AEAD cipher into a new ShadowStreamCipher.
func NewShadowStreamCipher(aead cipher.AEAD) *ShadowStreamCipher {
	return &ShadowStreamCipher{
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
	}
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

// readOnceExpectFull reads exactly once from r into b and
// returns an error if the read fails to fill up b.
func readOnceExpectFull(r io.Reader, b []byte) (int, error) {
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	if n < len(b) {
		return n, &HeaderError[int]{ErrFirstRead, len(b), n}
	}
	return n, nil
}

// readOnceOrFullFunc returns a function that either reads exactly once from r into b
// or reads until b is full, depending on the value of allowSegmentedFixedLengthHeader.
func readOnceOrFullFunc(allowSegmentedFixedLengthHeader bool) func(io.Reader, []byte) (int, error) {
	if allowSegmentedFixedLengthHeader {
		return io.ReadFull
	}
	return readOnceExpectFull
}

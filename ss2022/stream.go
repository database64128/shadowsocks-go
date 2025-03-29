package ss2022

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/database64128/shadowsocks-go/netio"
)

const (
	streamMaxPayloadSize    = 0xFFFF
	streamReadMinBufferSize = streamMaxPayloadSize + tagSize
	streamWriteBufferSize   = 2 + tagSize + streamMaxPayloadSize + tagSize
)

var (
	ErrZeroLengthChunk = errors.New("length in length chunk is zero")
	ErrFirstRead       = errors.New("failed to read fixed-length header in one read call")
	ErrRepeatedSalt    = errors.New("detected replay: repeated salt")
)

var ErrUnsafeStreamPrefixMismatch = errors.New("unsafe stream prefix mismatch")

// ShadowStreamServerConn is a server stream connection.
type ShadowStreamServerConn struct {
	ShadowStreamConn
	unsafeResponseStreamPrefix []byte
	cipherConfig               UserCipherConfig

	// Change type to [16]byte | [32]byte, once Go supports the necessary
	// slice operations over array type parameters.
	requestSalt    [32]byte
	requestSaltLen int
}

// WriteTo implements [io.WriterTo].
func (c *ShadowStreamServerConn) WriteTo(w io.Writer) (n int64, err error) {
	if w, ok := w.(*ShadowStreamClientConn); ok {
		return c.ShadowStreamConn.writeToShadowStreamConn(&w.ShadowStreamConn)
	}
	return c.ShadowStreamConn.WriteTo(w)
}

// Write implements [netio.Conn.Write].
func (c *ShadowStreamServerConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if c.ShadowStreamConn.writeCipher == nil { // first write
		hb, payloadBuf := c.prepareInitWriteBufs()
		payloadLen := min(len(payloadBuf), len(b))
		if err = c.initWrite(hb, b[:payloadLen]); err != nil {
			return 0, err
		}
		n += payloadLen
		if payloadLen < len(b) {
			var nn int
			nn, err = c.ShadowStreamConn.Write(b[payloadLen:])
			n += nn
		}
		return n, err
	}

	return c.ShadowStreamConn.Write(b)
}

// ReadFrom implements [io.ReaderFrom].
func (c *ShadowStreamServerConn) ReadFrom(r io.Reader) (n int64, err error) {
	if r, ok := r.(*ShadowStreamClientConn); ok {
		return r.writeToServerConn(c)
	}
	return c.readFromGeneric(r)
}

func (c *ShadowStreamServerConn) readFromGeneric(r io.Reader) (n int64, err error) {
	if c.ShadowStreamConn.writeCipher == nil { // first write
		hb, payloadBuf := c.prepareInitWriteBufs()

		for {
			nr, err := r.Read(payloadBuf)
			if nr > 0 {
				n = int64(nr)
				if err = c.initWrite(hb, payloadBuf[:nr]); err != nil {
					return n, err
				}
				break
			}
			if err != nil {
				if err == io.EOF {
					return n, nil
				}
				return n, err
			}
		}

		nn, err := c.ShadowStreamConn.ReadFrom(r)
		n += nn
		return n, err
	}

	return c.ShadowStreamConn.ReadFrom(r)
}

func (c *ShadowStreamServerConn) prepareInitWriteBufs() (hb, payloadBuf []byte) {
	urspLen := len(c.unsafeResponseStreamPrefix)
	saltLen := len(c.cipherConfig.PSK)
	responseHeaderStart := urspLen + saltLen
	responseHeaderEnd := responseHeaderStart + TCPRequestFixedLengthHeaderLength + saltLen
	payloadBufStart := responseHeaderEnd + tagSize
	// When ursp is unusually large, guarantee enough buffer space for at least 4096 bytes of payload.
	minBufferLen := payloadBufStart + 4096 + tagSize
	writeBuf := c.ShadowStreamConn.writeBuf
	if minBufferLen <= cap(writeBuf) {
		hb = writeBuf
	} else {
		hb = slices.Grow(hb, minBufferLen)
	}
	// Ensure payloadBuf is no larger than streamMaxPayloadSize.
	payloadBufEnd := min(payloadBufStart+streamMaxPayloadSize, cap(hb)-tagSize)
	return hb, hb[payloadBufStart:payloadBufEnd]
}

func (c *ShadowStreamServerConn) initWrite(hb, payload []byte) error {
	// Append unsafe response stream prefix.
	hb = append(hb, c.unsafeResponseStreamPrefix...)

	// Append random salt.
	dst := hb[:len(hb)+len(c.cipherConfig.PSK)]
	salt := dst[len(hb):]
	rand.Read(salt)

	// Append response header.
	hb = AppendTCPResponseHeader(dst, c.requestSalt[:c.requestSaltLen], uint16(len(payload)))

	// Create AEAD cipher.
	shadowStreamCipher, err := c.cipherConfig.ShadowStreamCipher(salt)
	if err != nil {
		return err
	}
	c.ShadowStreamConn.writeCipher = shadowStreamCipher

	// Seal response header.
	hb = shadowStreamCipher.EncryptAppend(dst, hb[len(dst):])

	// Seal payload chunk.
	hb = shadowStreamCipher.EncryptAppend(hb, payload)

	// Write to inner connection.
	_, err = c.ShadowStreamConn.Conn.Write(hb)
	return err
}

// ShadowStreamClientConn is a client stream connection.
type ShadowStreamClientConn struct {
	ShadowStreamConn
	readOnceOrFull             func(io.Reader, []byte) (int, error)
	unsafeResponseStreamPrefix []byte
	cipherConfig               *ClientCipherConfig

	// Change type to [16]byte | [32]byte, once Go supports the necessary
	// slice operations over array type parameters.
	requestSalt    [32]byte
	requestSaltLen int
}

// Read implements [netio.Conn.Read].
func (c *ShadowStreamClientConn) Read(b []byte) (n int, err error) {
	if c.ShadowStreamConn.readCipher == nil { // first read
		payloadLen, err := c.initRead(b)
		if err != nil {
			return 0, err
		}
		bufLen := payloadLen + tagSize

		// Happy path: b is large enough for the read.
		if bufLen <= len(b) {
			if err = c.readFirstPayloadChunk(b[:bufLen]); err != nil {
				return 0, err
			}
			return payloadLen, nil
		}

		readBuf := c.ShadowStreamConn.getReadBuf()
		if err = c.readFirstPayloadChunk(readBuf[:bufLen]); err != nil {
			return 0, err
		}
		readBuf = readBuf[:payloadLen]

		n = copy(b, readBuf)
		if n < payloadLen {
			c.ShadowStreamConn.readBuf = readBuf
			c.ShadowStreamConn.readStart = n
		}
		return n, nil
	}

	return c.ShadowStreamConn.Read(b)
}

// WriteTo implements [io.WriterTo].
func (c *ShadowStreamClientConn) WriteTo(w io.Writer) (n int64, err error) {
	if w, ok := w.(*ShadowStreamServerConn); ok {
		return c.writeToServerConn(w)
	}
	return c.writeToGeneric(w)
}

func (c *ShadowStreamClientConn) writeToServerConn(w *ShadowStreamServerConn) (n int64, err error) {
	if c.ShadowStreamConn.readCipher == nil { // first read
		b := w.writeBuf

		payloadLen, err := c.initRead(b[:cap(b)])
		if err != nil {
			if err == io.EOF {
				return 0, nil
			}
			return 0, err
		}

		readBuf := make([]byte, payloadLen+tagSize)
		if err = c.readFirstPayloadChunk(readBuf); err != nil {
			return 0, err
		}
		if _, err = w.Write(readBuf[:payloadLen]); err != nil {
			return 0, err
		}

		n, err = c.ShadowStreamConn.writeToShadowStreamConn(&w.ShadowStreamConn)
		n += int64(payloadLen)
		return n, err
	}

	return c.ShadowStreamConn.writeToShadowStreamConn(&w.ShadowStreamConn)
}

func (c *ShadowStreamClientConn) writeToGeneric(w io.Writer) (n int64, err error) {
	if c.ShadowStreamConn.readCipher == nil { // first read
		payloadLen, err := c.initRead(nil)
		if err != nil {
			if err == io.EOF {
				return 0, nil
			}
			return 0, err
		}

		readBuf := c.ShadowStreamConn.getReadBuf()
		if err = c.readFirstPayloadChunk(readBuf[:payloadLen+tagSize]); err != nil {
			return 0, err
		}
		nw, err := w.Write(readBuf[:payloadLen])
		n = int64(nw)
		if err != nil {
			return n, err
		}

		nn, err := c.ShadowStreamConn.WriteTo(w)
		n += nn
		return n, err
	}

	return c.ShadowStreamConn.WriteTo(w)
}

func (c *ShadowStreamClientConn) initRead(b []byte) (payloadLen int, err error) {
	urspLen := len(c.unsafeResponseStreamPrefix)
	saltLen := len(c.cipherConfig.PSK)
	fixedLengthHeaderStart := urspLen + saltLen
	bufferLen := fixedLengthHeaderStart + TCPRequestFixedLengthHeaderLength + saltLen + tagSize

	var hb []byte
	switch {
	case bufferLen <= len(b):
		hb = b[:bufferLen]
	case bufferLen <= streamReadMinBufferSize:
		hb = c.ShadowStreamConn.getReadBuf()[:bufferLen]
	default:
		hb = make([]byte, bufferLen)
	}

	// Read sealed response header.
	if _, err = c.readOnceOrFull(c.ShadowStreamConn.Conn, hb); err != nil {
		return 0, err
	}

	// Check unsafe response stream prefix.
	ursp := hb[:urspLen]
	if !bytes.Equal(ursp, c.unsafeResponseStreamPrefix) {
		return 0, &HeaderError[[]byte]{ErrUnsafeStreamPrefixMismatch, c.unsafeResponseStreamPrefix, ursp}
	}

	// Derive key and create cipher.
	salt := hb[urspLen:fixedLengthHeaderStart]
	ciphertext := hb[fixedLengthHeaderStart:]
	shadowStreamCipher, err := c.cipherConfig.ShadowStreamCipher(salt)
	if err != nil {
		return 0, err
	}
	c.ShadowStreamConn.readCipher = shadowStreamCipher

	// Open sealed response header.
	plaintext, err := shadowStreamCipher.DecryptInPlace(ciphertext)
	if err != nil {
		return 0, err
	}

	// Parse response header.
	payloadLen, err = ParseTCPResponseHeader(plaintext, c.requestSalt[:c.requestSaltLen])
	if err != nil {
		return 0, err
	}

	return payloadLen, nil
}

func (c *ShadowStreamClientConn) readFirstPayloadChunk(b []byte) error {
	// Read sealed payload chunk.
	if _, err := io.ReadFull(c.ShadowStreamConn.Conn, b); err != nil {
		return err
	}

	// Open sealed payload chunk.
	_, err := c.ShadowStreamConn.readCipher.DecryptInPlace(b)
	return err
}

// ReadFrom implements [io.ReaderFrom].
func (c *ShadowStreamClientConn) ReadFrom(r io.Reader) (n int64, err error) {
	if r, ok := r.(*ShadowStreamServerConn); ok {
		return r.ShadowStreamConn.writeToShadowStreamConn(&c.ShadowStreamConn)
	}
	return c.ShadowStreamConn.ReadFrom(r)
}

// ShadowStreamConn wraps a [netio.Conn] and provides an encrypted Shadowsocks stream over it.
//
// Wire format:
//
//	+------------------------+---------------------------+
//	| encrypted length chunk |  encrypted payload chunk  |
//	+------------------------+---------------------------+
//	|  2B length + 16B tag   | variable length + 16B tag |
//	+------------------------+---------------------------+
type ShadowStreamConn struct {
	netio.Conn

	readBuf    []byte // lazily allocated; length is readEnd
	readStart  int
	readCipher *ShadowStreamCipher

	writeBuf    []byte // non-nil; length is always 0
	writeCipher *ShadowStreamCipher
}

func (c *ShadowStreamConn) writeToShadowStreamConn(w *ShadowStreamConn) (n int64, err error) {
	writeBuf := w.writeBuf
	readBuf := writeBuf[2+tagSize : 2+tagSize]

	for {
		nr, err := c.read(readBuf)
		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}

		if err := w.write(writeBuf, readBuf[:nr]); err != nil {
			return n, err
		}
		n += int64(nr)
	}
}

func (c *ShadowStreamConn) getReadBuf() []byte {
	if c.readBuf == nil {
		c.readBuf = slices.Grow(c.readBuf, streamReadMinBufferSize)
	}
	return c.readBuf
}

// Read implements [netio.Conn.Read].
func (c *ShadowStreamConn) Read(b []byte) (n int, err error) {
	if c.readStart == len(c.readBuf) {
		// Happy path: b is large enough for the read.
		if len(b) >= streamReadMinBufferSize {
			return c.read(b)
		}

		readBuf := c.getReadBuf()

		n, err = c.read(readBuf)
		if err != nil {
			return 0, err
		}

		c.readBuf = readBuf[:n]
		c.readStart = 0
	}

	n = copy(b, c.readBuf[c.readStart:])
	c.readStart += n
	return n, nil
}

// WriteTo implements [io.WriterTo].
func (c *ShadowStreamConn) WriteTo(w io.Writer) (n int64, err error) {
	b := c.getReadBuf()

	for {
		nr, err := c.read(b)
		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}

		nw, err := w.Write(b[:nr])
		n += int64(nw)
		if err != nil {
			return n, err
		}
	}
}

func (c *ShadowStreamConn) read(b []byte) (n int, err error) {
	if cap(b) < streamReadMinBufferSize {
		panic(fmt.Sprintf("ss2022.ShadowStreamConn.read: buffer too small: %d < %d", cap(b), streamReadMinBufferSize))
	}

	// Read sealed length chunk.
	ciphertext := b[:2+tagSize]
	if _, err = io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	// Open sealed length chunk.
	if _, err = c.readCipher.DecryptInPlace(ciphertext); err != nil {
		return 0, err
	}

	// Validate length.
	length := int(binary.BigEndian.Uint16(ciphertext))
	if length == 0 {
		return 0, ErrZeroLengthChunk
	}

	// Read sealed payload chunk.
	ciphertext = b[:length+tagSize]
	if _, err = io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	// Open sealed payload chunk.
	if _, err = c.readCipher.DecryptInPlace(ciphertext); err != nil {
		return 0, err
	}

	return length, nil
}

// Write implements [netio.Conn.Write].
func (c *ShadowStreamConn) Write(b []byte) (n int, err error) {
	writeBuf := c.writeBuf

	for len(b) > 0 {
		length := min(len(b), streamMaxPayloadSize)

		if err = c.write(writeBuf, b[:length]); err != nil {
			return n, err
		}

		n += length
		b = b[length:]
	}

	return n, nil
}

// ReadFrom implements [io.ReaderFrom].
func (c *ShadowStreamConn) ReadFrom(r io.Reader) (n int64, err error) {
	writeBuf := c.writeBuf
	payloadBuf := writeBuf[2+tagSize : 2+tagSize+streamMaxPayloadSize]

	for {
		nr, err := r.Read(payloadBuf)
		if nr > 0 {
			n += int64(nr)
			if err := c.write(writeBuf, payloadBuf[:nr]); err != nil {
				return n, err
			}
		}
		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
	}
}

func (c *ShadowStreamConn) write(b, payload []byte) error {
	// Append length.
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))

	// Seal length chunk.
	b = c.writeCipher.EncryptInPlace(b)

	// Seal payload chunk.
	b = c.writeCipher.EncryptAppend(b, payload)

	// Write to inner connection.
	_, err := c.Conn.Write(b)
	return err
}

// ShadowStreamCipher wraps an AEAD cipher and provides methods that transparently increments
// the nonce after each AEAD operation.
type ShadowStreamCipher struct {
	aead  cipher.AEAD
	nonce [nonceSize]byte
}

// NewShadowStreamCipher wraps the given AEAD cipher into a new ShadowStreamCipher.
func NewShadowStreamCipher(aead cipher.AEAD) *ShadowStreamCipher {
	return &ShadowStreamCipher{
		aead: aead,
	}
}

// EncryptInPlace encrypts and authenticates plaintext in-place.
func (c *ShadowStreamCipher) EncryptInPlace(plaintext []byte) (ciphertext []byte) {
	ciphertext = c.aead.Seal(plaintext[:0], c.nonce[:], plaintext, nil)
	increment(c.nonce[:])
	return
}

// EncryptTo encrypts and authenticates the plaintext and saves the ciphertext to dst.
func (c *ShadowStreamCipher) EncryptTo(dst, plaintext []byte) (ciphertext []byte) {
	ciphertext = c.aead.Seal(dst[:0], c.nonce[:], plaintext, nil)
	increment(c.nonce[:])
	return
}

// EncryptAppend encrypts and authenticates plaintext and appends the ciphertext to dst.
func (c *ShadowStreamCipher) EncryptAppend(dst, plaintext []byte) (ciphertext []byte) {
	ciphertext = c.aead.Seal(dst, c.nonce[:], plaintext, nil)
	increment(c.nonce[:])
	return
}

// DecryptInplace decrypts and authenticates ciphertext in-place.
func (c *ShadowStreamCipher) DecryptInPlace(ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(ciphertext[:0], c.nonce[:], ciphertext, nil)
	if err == nil {
		increment(c.nonce[:])
	}
	return
}

// DecryptTo decrypts and authenticates the ciphertext and saves the plaintext to dst.
func (c *ShadowStreamCipher) DecryptTo(dst, ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(dst[:0], c.nonce[:], ciphertext, nil)
	if err == nil {
		increment(c.nonce[:])
	}
	return
}

// DecryptAppend decrypts and authenticates ciphertext and appends the plaintext to dst.
func (c *ShadowStreamCipher) DecryptAppend(dst, ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = c.aead.Open(dst, c.nonce[:], ciphertext, nil)
	if err == nil {
		increment(c.nonce[:])
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
		if err == io.EOF && 0 < n && n < len(b) {
			return n, io.ErrUnexpectedEOF
		}
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

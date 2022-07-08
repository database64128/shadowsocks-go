package zerocopy

import (
	"bytes"
	"io"
	"testing"
)

// defaultBufferSize is the default buffer size to use
// when neither the reader nor the writer has buffer size requirements.
// It's the same default as io.Copy.
const defaultBufferSize = 32768

// Reader provides a stream interface for reading.
type Reader interface {
	Headroom

	// MinPayloadBufferSizePerRead returns the minimum size of payload buffer
	// the ReadZeroCopy method requires for an unbuffered read.
	//
	// This is usually required by chunk-based protocols to be able to read
	// whole chunks without needing internal caching.
	MinPayloadBufferSizePerRead() int

	// ReadZeroCopy uses b as buffer space to initiate a read operation.
	//
	// b must have at least FrontOverhead() bytes before payloadBufStart
	// and RearOverhead() bytes after payloadBufStart + payloadBufLen.
	//
	// payloadBufLen must be at least MinPayloadBufferSizePerRead().
	//
	// The read operation may use the whole space of b.
	// The actual payload will be confined in [payloadBufStart, payloadBufLen).
	//
	// If no error occurs, the returned payload is b[payloadBufStart : payloadBufStart+payloadLen].
	ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error)

	io.Closer
}

// Writer provides a stream interface for writing.
type Writer interface {
	Headroom

	// MaxPayloadSizePerWrite returns the maximum size of payload
	// the WriteZeroCopy method can write at a time.
	//
	// This is usually required by chunk-based protocols to be able to write
	// one chunk at a time without needing to break up the payload.
	//
	// If there isn't a maximum limit, return 0.
	MaxPayloadSizePerWrite() int

	// WriteZeroCopy uses b as buffer space to initiate a write operation.
	//
	// b must have at least FrontOverhead() bytes before payloadBufStart
	// and RearOverhead() bytes after payloadBufStart + payloadBufLen.
	//
	// payloadLen must not be greater than MaxPayloadSizePerWrite().
	//
	// The write operation may use the whole space of b.
	WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error)

	io.Closer
}

// DirectReadCloser provides access to the underlying io.ReadCloser.
type DirectReadCloser interface {
	// DirectReadCloser returns the underlying reader for direct reads.
	DirectReadCloser() io.ReadCloser
}

// DirectWriteCloser provides access to the underlying io.WriteCloser.
type DirectWriteCloser interface {
	// DirectWriteCloser returns the underlying writer for direct writes.
	DirectWriteCloser() io.WriteCloser
}

// Relay reads from r and writes to w using zero-copy methods.
// It returns the number of bytes transferred, and any error occurred during transfer.
func Relay(w Writer, r Reader) (n int64, err error) {
	// Use direct read/write when possible.
	if dr, ok := r.(DirectReadCloser); ok {
		if dw, ok := w.(DirectWriteCloser); ok {
			r := dr.DirectReadCloser()
			w := dw.DirectWriteCloser()
			n, err = io.Copy(w, r)
			cwErr := w.Close()
			if err == nil {
				err = cwErr
			}
			return
		}
	}

	// Determine front headroom.
	frontHeadroom := r.FrontHeadroom()
	wfh := w.FrontHeadroom()
	if wfh > frontHeadroom {
		frontHeadroom = wfh
	}

	// Determine rear headroom.
	rearHeadroom := r.RearHeadroom()
	wrh := w.RearHeadroom()
	if wrh > rearHeadroom {
		rearHeadroom = wrh
	}

	// Check payload buffer size requirement compatibility.
	readMaxPayloadSize := r.MinPayloadBufferSizePerRead()
	writeMaxPayloadSize := w.MaxPayloadSizePerWrite()
	if writeMaxPayloadSize == 0 {
		writeMaxPayloadSize = readMaxPayloadSize
		if writeMaxPayloadSize == 0 {
			writeMaxPayloadSize = defaultBufferSize
		}
	}
	if readMaxPayloadSize > writeMaxPayloadSize {
		return relayFallback(w, r, frontHeadroom, rearHeadroom, readMaxPayloadSize, writeMaxPayloadSize)
	}

	// Make buffer.
	b := make([]byte, frontHeadroom+writeMaxPayloadSize+rearHeadroom)

	// Main relay loop.
	for {
		var payloadLen int
		payloadLen, err = r.ReadZeroCopy(b, frontHeadroom, writeMaxPayloadSize)
		if payloadLen == 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}

		payloadWritten, werr := w.WriteZeroCopy(b, frontHeadroom, payloadLen)
		n += int64(payloadWritten)
		if werr != nil {
			err = werr
		}

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

// relayFallback uses copying to handle situations where the reader requires more payload buffer space than the writer can handle in one write call.
func relayFallback(w Writer, r Reader, frontHeadroom, rearHeadroom, readMaxPayloadSize, writeMaxPayloadSize int) (n int64, err error) {
	br := make([]byte, frontHeadroom+readMaxPayloadSize+rearHeadroom)
	bw := make([]byte, frontHeadroom+writeMaxPayloadSize+rearHeadroom)

	for {
		var payloadLen int
		payloadLen, err = r.ReadZeroCopy(br, frontHeadroom, readMaxPayloadSize)
		if payloadLen == 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}

		// Short-circuit to avoid copying if payload can fit in one write.
		if payloadLen <= writeMaxPayloadSize {
			payloadWritten, werr := w.WriteZeroCopy(br, frontHeadroom, payloadLen)
			n += int64(payloadWritten)
			if werr != nil {
				err = werr
			}
			if err != nil {
				return
			}
			continue
		}

		// Loop until all of br[frontHeadroom : frontHeadroom+payloadLen] is written.
		for i, j := 0, 0; i < payloadLen; i += j {
			j = copy(bw[frontHeadroom:frontHeadroom+writeMaxPayloadSize], br[frontHeadroom+i:frontHeadroom+payloadLen])
			payloadWritten, werr := w.WriteZeroCopy(bw, frontHeadroom, j)
			n += int64(payloadWritten)
			if werr != nil {
				err = werr
				break
			}
		}

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

// CloseRead provides the CloseRead method.
type CloseRead interface {
	// CloseRead indicates to the underlying reader that no further reads will happen.
	CloseRead() error
}

// CloseWrite provides the CloseWrite method.
type CloseWrite interface {
	// CloseWrite indicates to the underlying writer that no further writes will happen.
	CloseWrite() error
}

// ReadWriter provides a stream interface for reading and writing.
type ReadWriter interface {
	Reader
	Writer
	CloseRead
	CloseWrite
}

// TwoWayRelay relays data between left and right using zero-copy methods.
// It returns the number of bytes sent from left to right, from right to left,
// and any error occurred during transfer.
func TwoWayRelay(left, right ReadWriter) (nl2r, nr2l int64, err error) {
	var (
		l2rErr error
		lcwErr error
		rcwErr error
	)

	ctrlCh := make(chan struct{})

	go func() {
		nl2r, l2rErr = Relay(right, left)
		rcwErr = right.CloseWrite()
		ctrlCh <- struct{}{}
	}()

	nr2l, err = Relay(left, right)
	lcwErr = left.CloseWrite()
	<-ctrlCh

	switch {
	case err != nil:
	case l2rErr != nil:
		err = l2rErr
	case lcwErr != nil:
		err = lcwErr
	case rcwErr != nil:
		err = rcwErr
	}
	return
}

// DirectReadWriteCloser extends io.ReadWriteCloser with CloseRead and CloseWrite.
type DirectReadWriteCloser interface {
	io.ReadWriteCloser
	CloseRead
	CloseWrite
}

// ReadWriterTestFunc tests the left and right ReadWriters by performing 2 writes
// on each ReadWriter and validating the read results.
//
// The left and right ReadWriters must be connected with a duplex pipe.
func ReadWriterTestFunc(t *testing.T, l, r ReadWriter) {
	defer r.Close()
	defer l.Close()

	var (
		hello = []byte{'h', 'e', 'l', 'l', 'o'}
		world = []byte{'w', 'o', 'r', 'l', 'd'}
	)

	lfh := l.FrontHeadroom()
	lrh := l.RearHeadroom()
	lmax := l.MaxPayloadSizePerWrite()
	if lmax == 0 {
		lmax = 5
	}
	lmin := l.MinPayloadBufferSizePerRead()
	if lmin == 0 {
		lmin = 5
	}
	lwbuf := make([]byte, lfh+lmax+lrh)
	lrbuf := make([]byte, lfh+lmin+lrh)

	rfh := r.FrontHeadroom()
	rrh := r.RearHeadroom()
	rmax := r.MaxPayloadSizePerWrite()
	if rmax == 0 {
		rmax = 5
	}
	rmin := r.MinPayloadBufferSizePerRead()
	if rmin == 0 {
		rmin = 5
	}
	rwbuf := make([]byte, rfh+rmax+rrh)
	rrbuf := make([]byte, rfh+rmin+rrh)

	ctrlCh := make(chan struct{})

	// Start read goroutines.
	go func() {
		pl, err := l.ReadZeroCopy(lrbuf, lfh, lmax)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p := lrbuf[lfh : lfh+pl]
		if !bytes.Equal(p, world) {
			t.Errorf("Expected payload %v, got %v", world, p)
		}

		pl, err = l.ReadZeroCopy(lrbuf, lfh, lmax)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p = lrbuf[lfh : lfh+pl]
		if !bytes.Equal(p, hello) {
			t.Errorf("Expected payload %v, got %v", hello, p)
		}

		pl, err = l.ReadZeroCopy(lrbuf, lfh, lmax)
		if err != io.EOF {
			t.Errorf("Expected io.EOF, got %v", err)
		}
		if pl != 0 {
			t.Errorf("Expected payloadLen 0, got %v", pl)
		}

		ctrlCh <- struct{}{}
	}()

	go func() {
		pl, err := r.ReadZeroCopy(rrbuf, rfh, rmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p := rrbuf[rfh : rfh+pl]
		if !bytes.Equal(p, hello) {
			t.Errorf("Expected payload %v, got %v", hello, p)
		}

		pl, err = r.ReadZeroCopy(rrbuf, rfh, rmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p = rrbuf[rfh : rfh+pl]
		if !bytes.Equal(p, world) {
			t.Errorf("Expected payload %v, got %v", world, p)
		}

		pl, err = r.ReadZeroCopy(rrbuf, rfh, rmin)
		if err != io.EOF {
			t.Errorf("Expected io.EOF, got %v", err)
		}
		if pl != 0 {
			t.Errorf("Expected payloadLen 0, got %v", pl)
		}

		ctrlCh <- struct{}{}
	}()

	// Write from left to right.
	n := copy(lwbuf[lfh:], hello)
	written, err := l.WriteZeroCopy(lwbuf, lfh, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	n = copy(lwbuf[lfh:], world)
	written, err = l.WriteZeroCopy(lwbuf, lfh, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	err = l.CloseWrite()
	if err != nil {
		t.Error(err)
	}

	// Write from right to left.
	n = copy(rwbuf[rfh:], world)
	written, err = r.WriteZeroCopy(rwbuf, rfh, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	n = copy(rwbuf[rfh:], hello)
	written, err = r.WriteZeroCopy(rwbuf, rfh, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	err = r.CloseWrite()
	if err != nil {
		t.Error(err)
	}

	<-ctrlCh
	<-ctrlCh
}

// CopyReadWriter wraps a ReadWriter and provides the io.ReadWriter Read and Write methods
// by copying from and to internal buffers and using the zerocopy methods on them.
type CopyReadWriter struct {
	ReadWriter

	frontHeadroom int
	rearHeadroom  int

	readBuf       []byte
	readBufStart  int
	readBufLength int

	writeBuf []byte
}

func NewCopyReadWriter(rw ReadWriter) *CopyReadWriter {
	frontHeadroom := rw.FrontHeadroom()
	rearHeadroom := rw.RearHeadroom()

	readBufSize := rw.MinPayloadBufferSizePerRead()
	if readBufSize == 0 {
		readBufSize = defaultBufferSize
	}

	writeBufSize := rw.MaxPayloadSizePerWrite()
	if writeBufSize == 0 {
		writeBufSize = defaultBufferSize
	}

	return &CopyReadWriter{
		ReadWriter:    rw,
		frontHeadroom: frontHeadroom,
		rearHeadroom:  rearHeadroom,
		readBuf:       make([]byte, frontHeadroom+readBufSize+rearHeadroom),
		writeBuf:      make([]byte, frontHeadroom+writeBufSize+rearHeadroom),
	}
}

// Read implements the io.Reader Read method.
func (rw *CopyReadWriter) Read(b []byte) (n int, err error) {
	if rw.readBufLength == 0 {
		rw.readBufStart = rw.frontHeadroom
		rw.readBufLength = len(rw.readBuf) - rw.frontHeadroom - rw.rearHeadroom
		rw.readBufLength, err = rw.ReadWriter.ReadZeroCopy(rw.readBuf, rw.readBufStart, rw.readBufLength)
		if err != nil {
			return
		}
	}

	n = copy(b, rw.readBuf[rw.readBufStart:rw.readBufStart+rw.readBufLength])
	rw.readBufStart += n
	rw.readBufLength -= n
	return n, nil
}

// Write implements the io.Writer Write method.
func (rw *CopyReadWriter) Write(b []byte) (n int, err error) {
	payloadBuf := rw.writeBuf[rw.frontHeadroom : len(rw.writeBuf)-rw.rearHeadroom]

	for n < len(b) {
		payloadLength := copy(payloadBuf, b[n:])
		var payloadWritten int
		payloadWritten, err = rw.ReadWriter.WriteZeroCopy(rw.writeBuf, rw.frontHeadroom, payloadLength)
		n += payloadWritten
		if err != nil {
			return
		}
	}

	return
}

func CopyWriteOnce(rw ReadWriter, b []byte) (n int, err error) {
	frontHeadroom := rw.FrontHeadroom()
	rearHeadroom := rw.RearHeadroom()

	writeBufSize := rw.MaxPayloadSizePerWrite()
	if writeBufSize == 0 {
		writeBufSize = defaultBufferSize
	}

	writeBuf := make([]byte, frontHeadroom+writeBufSize+rearHeadroom)
	payloadBuf := writeBuf[frontHeadroom : frontHeadroom+writeBufSize]

	for n < len(b) {
		payloadLength := copy(payloadBuf, b[n:])
		var payloadWritten int
		payloadWritten, err = rw.WriteZeroCopy(writeBuf, frontHeadroom, payloadLength)
		n += payloadWritten
		if err != nil {
			return
		}
	}

	return
}

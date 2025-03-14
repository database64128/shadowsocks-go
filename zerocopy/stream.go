package zerocopy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
)

// defaultBufferSize is the default buffer size to use
// when neither the reader nor the writer has buffer size requirements.
// It's the same default as io.Copy.
const defaultBufferSize = 32768

// ReaderInfo contains information about a reader.
type ReaderInfo struct {
	Headroom Headroom

	// MinPayloadBufferSizePerRead is the minimum size of payload buffer
	// the ReadZeroCopy method requires for an unbuffered read.
	//
	// This is usually required by chunk-based protocols to be able to read
	// whole chunks without needing internal caching.
	MinPayloadBufferSizePerRead int
}

// Reader provides a stream interface for reading.
type Reader interface {
	// ReaderInfo returns information about the reader.
	ReaderInfo() ReaderInfo

	// ReadZeroCopy uses b as buffer space to initiate a read operation.
	//
	// b must have at least [ReaderInfo.Headroom.Front] bytes before payloadBufStart
	// and [ReaderInfo.Headroom.Rear] bytes after payloadBufStart + payloadBufLen.
	//
	// payloadBufLen must be at least [ReaderInfo.MinPayloadBufferSizePerRead].
	//
	// The read operation may use the whole space of b.
	// The actual payload will be confined in [payloadBufStart, payloadBufLen).
	//
	// If no error occurs, the returned payload is b[payloadBufStart : payloadBufStart+payloadLen].
	ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error)
}

// WriterInfo contains information about a writer.
type WriterInfo struct {
	Headroom Headroom

	// MaxPayloadSizePerWrite is the maximum size of payload
	// the WriteZeroCopy method can write at a time.
	//
	// This is usually required by chunk-based protocols to be able to write
	// one chunk at a time without needing to break up the payload.
	//
	// 0 means no size limit.
	MaxPayloadSizePerWrite int
}

// Writer provides a stream interface for writing.
type Writer interface {
	// WriterInfo returns information about the writer.
	WriterInfo() WriterInfo

	// WriteZeroCopy uses b as buffer space to initiate a write operation.
	//
	// b must have at least [WriterInfo.Headroom.Front] bytes before payloadBufStart
	// and [WriterInfo.Headroom.Rear] bytes after payloadBufStart + payloadBufLen.
	//
	// payloadLen must not exceed [WriterInfo.MaxPayloadSizePerWrite].
	//
	// The write operation may use the whole space of b.
	WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error)
}

// DirectReader provides access to the underlying [io.Reader].
type DirectReader interface {
	// DirectReader returns the underlying reader for direct reads.
	DirectReader() io.Reader
}

// DirectWriter provides access to the underlying [io.Writer].
type DirectWriter interface {
	// DirectWriter returns the underlying writer for direct writes.
	DirectWriter() io.Writer
}

// Relay reads from r and writes to w using zero-copy methods.
// It returns the number of bytes transferred, and any error occurred during transfer.
func Relay(w Writer, r Reader) (n int64, err error) {
	// Use direct read/write when possible.
	if dr, ok := r.(DirectReader); ok {
		if dw, ok := w.(DirectWriter); ok {
			r := dr.DirectReader()
			w := dw.DirectWriter()
			return io.Copy(w, r)
		}
	}

	// Process reader and writer info.
	ri := r.ReaderInfo()
	wi := w.WriterInfo()
	headroom := MaxHeadroom(ri.Headroom, wi.Headroom)

	// Check payload buffer size requirement compatibility.
	if wi.MaxPayloadSizePerWrite > 0 && ri.MinPayloadBufferSizePerRead > wi.MaxPayloadSizePerWrite {
		return relayFallback(w, r, headroom.Front, headroom.Rear, ri.MinPayloadBufferSizePerRead, wi.MaxPayloadSizePerWrite)
	}

	payloadBufSize := ri.MinPayloadBufferSizePerRead
	if payloadBufSize == 0 {
		payloadBufSize = wi.MaxPayloadSizePerWrite
		if payloadBufSize == 0 {
			payloadBufSize = defaultBufferSize
		}
	}

	// Make buffer.
	b := make([]byte, headroom.Front+payloadBufSize+headroom.Rear)

	// Main relay loop.
	for {
		var payloadLen int
		payloadLen, err = r.ReadZeroCopy(b, headroom.Front, payloadBufSize)
		if payloadLen == 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}

		payloadWritten, werr := w.WriteZeroCopy(b, headroom.Front, payloadLen)
		n += int64(payloadWritten)
		if werr != nil {
			err = werr
			return
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
				return
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
	io.Closer
}

// TwoWayRelay relays data between left and right using zero-copy methods.
// It returns the number of bytes sent from left to right, from right to left,
// and any error occurred during transfer.
func TwoWayRelay(left, right ReadWriter) (nl2r, nr2l int64, err error) {
	var (
		wg     sync.WaitGroup
		l2rErr error
	)

	wg.Add(1)
	go func() {
		nl2r, l2rErr = Relay(right, left)
		_ = right.CloseWrite()
		wg.Done()
	}()

	nr2l, err = Relay(left, right)
	_ = left.CloseWrite()
	wg.Wait()

	return nl2r, nr2l, errors.Join(l2rErr, err)
}

// DirectReadWriteCloser extends io.ReadWriteCloser with CloseRead and CloseWrite.
type DirectReadWriteCloser interface {
	io.ReadWriteCloser
	CloseRead
	CloseWrite
}

// DirectReadWriteCloserOpener provides the Open method to open a [DirectReadWriteCloser].
type DirectReadWriteCloserOpener interface {
	// Open opens a [DirectReadWriteCloser] with the specified initial payload.
	Open(ctx context.Context, b []byte) (DirectReadWriteCloser, error)
}

// SimpleDirectReadWriteCloserOpener wraps a [DirectReadWriteCloser] for the Open method to return.
type SimpleDirectReadWriteCloserOpener struct {
	DirectReadWriteCloser
}

// Open implements the DirectReadWriteCloserOpener Open method.
func (o *SimpleDirectReadWriteCloserOpener) Open(ctx context.Context, b []byte) (DirectReadWriteCloser, error) {
	_, err := o.DirectReadWriteCloser.Write(b)
	return o.DirectReadWriteCloser, err
}

// ReadWriterTestFunc tests the left and right ReadWriters by performing 2 writes
// on each ReadWriter and validating the read results.
//
// The left and right ReadWriters must be connected with a duplex pipe.
func ReadWriterTestFunc(t tester, l, r ReadWriter) {
	defer r.Close()
	defer l.Close()

	var (
		hello = []byte{'h', 'e', 'l', 'l', 'o'}
		world = []byte{'w', 'o', 'r', 'l', 'd'}
	)

	lri := l.ReaderInfo()
	lwi := l.WriterInfo()
	lwmax := lwi.MaxPayloadSizePerWrite
	if lwmax == 0 {
		lwmax = 5
	}
	lrmin := lri.MinPayloadBufferSizePerRead
	if lrmin == 0 {
		lrmin = 5
	}
	lwbuf := make([]byte, lwi.Headroom.Front+lwmax+lwi.Headroom.Rear)
	lrbuf := make([]byte, lri.Headroom.Front+lrmin+lri.Headroom.Rear)

	rri := r.ReaderInfo()
	rwi := r.WriterInfo()
	rwmax := rwi.MaxPayloadSizePerWrite
	if rwmax == 0 {
		rwmax = 5
	}
	rrmin := rri.MinPayloadBufferSizePerRead
	if rrmin == 0 {
		rrmin = 5
	}
	rwbuf := make([]byte, rwi.Headroom.Front+rwmax+rwi.Headroom.Rear)
	rrbuf := make([]byte, rri.Headroom.Front+rrmin+rri.Headroom.Rear)

	var wg sync.WaitGroup
	wg.Add(2)

	// Start read goroutines.
	go func() {
		defer wg.Done()

		pl, err := l.ReadZeroCopy(lrbuf, lri.Headroom.Front, lrmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p := lrbuf[lri.Headroom.Front : lri.Headroom.Front+pl]
		if !bytes.Equal(p, world) {
			t.Errorf("Expected payload %v, got %v", world, p)
		}

		pl, err = l.ReadZeroCopy(lrbuf, lri.Headroom.Front, lrmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p = lrbuf[lri.Headroom.Front : lri.Headroom.Front+pl]
		if !bytes.Equal(p, hello) {
			t.Errorf("Expected payload %v, got %v", hello, p)
		}

		pl, err = l.ReadZeroCopy(lrbuf, lri.Headroom.Front, lrmin)
		if err != io.EOF {
			t.Errorf("Expected io.EOF, got %v", err)
		}
		if pl != 0 {
			t.Errorf("Expected payloadLen 0, got %v", pl)
		}
	}()

	go func() {
		defer wg.Done()

		pl, err := r.ReadZeroCopy(rrbuf, rri.Headroom.Front, rrmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p := rrbuf[rri.Headroom.Front : rri.Headroom.Front+pl]
		if !bytes.Equal(p, hello) {
			t.Errorf("Expected payload %v, got %v", hello, p)
		}

		pl, err = r.ReadZeroCopy(rrbuf, rri.Headroom.Front, rrmin)
		if err != nil {
			t.Error(err)
		}
		if pl != 5 {
			t.Errorf("Expected payloadLen 5, got %d", pl)
		}
		p = rrbuf[rri.Headroom.Front : rri.Headroom.Front+pl]
		if !bytes.Equal(p, world) {
			t.Errorf("Expected payload %v, got %v", world, p)
		}

		pl, err = r.ReadZeroCopy(rrbuf, rri.Headroom.Front, rrmin)
		if err != io.EOF {
			t.Errorf("Expected io.EOF, got %v", err)
		}
		if pl != 0 {
			t.Errorf("Expected payloadLen 0, got %v", pl)
		}
	}()

	// Write from left to right.
	n := copy(lwbuf[lwi.Headroom.Front:], hello)
	written, err := l.WriteZeroCopy(lwbuf, lwi.Headroom.Front, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	n = copy(lwbuf[lwi.Headroom.Front:], world)
	written, err = l.WriteZeroCopy(lwbuf, lwi.Headroom.Front, n)
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
	n = copy(rwbuf[rwi.Headroom.Front:], world)
	written, err = r.WriteZeroCopy(rwbuf, rwi.Headroom.Front, n)
	if err != nil {
		t.Error(err)
	}
	if written != n {
		t.Errorf("Expected bytes written: %d, got %d", n, written)
	}

	n = copy(rwbuf[rwi.Headroom.Front:], hello)
	written, err = r.WriteZeroCopy(rwbuf, rwi.Headroom.Front, n)
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

	wg.Wait()
}

// CopyReader implements [io.Reader] for a [Reader] by copying in and out of an internal buffer.
// [io.WriterTo] is implemented using the same buffer.
type CopyReader struct {
	Reader
	buf             []byte
	payloadBufStart int
	payloadBufLen   int
	copyStart       int
	copyEnd         int
}

// NewCopyReader returns a new [CopyReader] for the given [Reader].
func NewCopyReader(r Reader) *CopyReader {
	ri := r.ReaderInfo()
	payloadBufLen := ri.MinPayloadBufferSizePerRead
	if payloadBufLen == 0 {
		payloadBufLen = defaultBufferSize
	}
	return &CopyReader{
		Reader:          r,
		buf:             make([]byte, ri.Headroom.Front+payloadBufLen+ri.Headroom.Rear),
		payloadBufStart: ri.Headroom.Front,
		payloadBufLen:   payloadBufLen,
	}
}

// Read implements [io.Reader].
func (r *CopyReader) Read(b []byte) (n int, err error) {
	if r.copyStart == r.copyEnd {
		n, err = r.Reader.ReadZeroCopy(r.buf, r.payloadBufStart, r.payloadBufLen)
		if n == 0 {
			return 0, err
		}
		r.copyStart = r.payloadBufStart
		r.copyEnd = r.payloadBufStart + n
	}
	n = copy(b, r.buf[r.copyStart:r.copyEnd])
	r.copyStart += n
	return n, err
}

// WriteTo implements [io.WriterTo].
func (r *CopyReader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		if r.copyStart == r.copyEnd {
			pl, err := r.Reader.ReadZeroCopy(r.buf, r.payloadBufStart, r.payloadBufLen)
			if pl == 0 {
				if err == io.EOF {
					return n, nil
				}
				return n, err
			}
			r.copyStart = r.payloadBufStart
			r.copyEnd = r.payloadBufStart + pl
		}

		wn, werr := w.Write(r.buf[r.copyStart:r.copyEnd])
		n += int64(wn)
		r.copyStart += wn
		if werr != nil {
			return n, werr
		}
	}
}

// CopyWriter implements [io.Writer] for a [Writer] by copying in and out of an internal buffer.
// [io.ReaderFrom] is implemented using the same buffer.
type CopyWriter struct {
	Writer
	buf          []byte
	payloadStart int
	payloadEnd   int
}

// NewCopyWriter returns a new [CopyWriter] for the given [Writer].
func NewCopyWriter(w Writer) *CopyWriter {
	wi := w.WriterInfo()
	payloadBufLen := wi.MaxPayloadSizePerWrite
	if payloadBufLen == 0 {
		payloadBufLen = defaultBufferSize
	}
	payloadEnd := wi.Headroom.Front + payloadBufLen
	return &CopyWriter{
		Writer:       w,
		buf:          make([]byte, payloadEnd+wi.Headroom.Rear),
		payloadStart: wi.Headroom.Front,
		payloadEnd:   payloadEnd,
	}
}

// Write implements [io.Writer].
func (w *CopyWriter) Write(b []byte) (n int, err error) {
	payloadBuf := w.buf[w.payloadStart:w.payloadEnd]
	for n < len(b) {
		payloadLen := copy(payloadBuf, b[n:])
		payloadWritten, err := w.Writer.WriteZeroCopy(w.buf, w.payloadStart, payloadLen)
		n += payloadWritten
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// ReadFrom implements [io.ReaderFrom].
func (w *CopyWriter) ReadFrom(r io.Reader) (n int64, err error) {
	payloadBuf := w.buf[w.payloadStart:w.payloadEnd]
	for {
		nr, err := r.Read(payloadBuf)
		if nr > 0 {
			n += int64(nr)
			if _, err := w.Writer.WriteZeroCopy(w.buf, w.payloadStart, nr); err != nil {
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

// CopyReadWriter joins a [CopyReader] and a [CopyWriter] into a single [ReadWriter].
type CopyReadWriter struct {
	CopyReader
	CopyWriter
}

// NewCopyReadWriter returns a new [CopyReadWriter] for the given [ReadWriter].
func NewCopyReadWriter(rw ReadWriter) *CopyReadWriter {
	return &CopyReadWriter{
		CopyReader: *NewCopyReader(rw),
		CopyWriter: *NewCopyWriter(rw),
	}
}

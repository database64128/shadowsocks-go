package zerocopy

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

type testBytesReadCloser struct {
	*bytes.Reader
}

func (r *testBytesReadCloser) Close() error {
	return nil
}

type testReader struct {
	ZeroHeadroom
	t *testing.T
	r *testBytesReadCloser
}

func newTestReader(t *testing.T) (*testReader, []byte) {
	b := make([]byte, 1024)
	bcopy := make([]byte, 1024)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	copy(bcopy, b)
	return &testReader{
		t: t,
		r: &testBytesReadCloser{bytes.NewReader(b)},
	}, bcopy
}

func (r *testReader) MinPayloadBufferSizePerRead() int {
	return 0
}

func (r *testReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	readBuf := b[payloadBufStart : payloadBufStart+payloadBufLen]
	payloadLen, err = r.r.Read(readBuf)
	return
}

func (r *testReader) Close() error {
	return nil
}

type testBigReader struct {
	*testReader
}

func newTestBigReader(t *testing.T) (*testBigReader, []byte) {
	r, b := newTestReader(t)
	return &testBigReader{
		testReader: r,
	}, b
}

func (r *testBigReader) MinPayloadBufferSizePerRead() int {
	return 64
}

func (r *testBigReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	if len(b) < 64 {
		r.t.Errorf("The read buffer is too small: %d", len(b))
	}
	return r.testReader.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

type testDirectReadCloser struct {
	*testReader
}

func newTestDirectReadCloser(t *testing.T) (*testDirectReadCloser, []byte) {
	r, b := newTestReader(t)
	return &testDirectReadCloser{
		testReader: r,
	}, b
}

func (r *testDirectReadCloser) DirectReadCloser() io.ReadCloser {
	return r.r
}

func (r *testDirectReadCloser) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	r.t.Error("Buffered relay method is used!")
	return
}

type testBytesBufferCloser struct {
	*bytes.Buffer
}

func (w *testBytesBufferCloser) Close() error {
	return nil
}

type testWriter struct {
	ZeroHeadroom
	t *testing.T
	w *testBytesBufferCloser
}

func newTestWriter(t *testing.T) *testWriter {
	b := make([]byte, 0, 1024)
	return &testWriter{
		t: t,
		w: &testBytesBufferCloser{bytes.NewBuffer(b)},
	}
}

func (w *testWriter) MaxPayloadSizePerWrite() int {
	return 0
}

func (w *testWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	writeBuf := b[payloadStart : payloadStart+payloadLen]
	payloadWritten, err = w.w.Write(writeBuf)
	return
}

func (w *testWriter) Close() error {
	return nil
}

func (w *testWriter) Bytes() []byte {
	return w.w.Bytes()
}

type testSmallWriter struct {
	*testWriter
}

func newTestSmallWriter(t *testing.T) *testSmallWriter {
	return &testSmallWriter{
		testWriter: newTestWriter(t),
	}
}

func (w *testSmallWriter) MaxPayloadSizePerWrite() int {
	return 32
}

func (w *testSmallWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	if len(b) > 32 {
		w.t.Errorf("The write buffer is too big: %d", len(b))
	}
	return w.testWriter.WriteZeroCopy(b, payloadStart, payloadLen)
}

type testDirectWriteCloser struct {
	*testWriter
}

func newTestDirectWriteCloser(t *testing.T) *testDirectWriteCloser {
	return &testDirectWriteCloser{
		testWriter: newTestWriter(t),
	}
}

func (w *testDirectWriteCloser) DirectWriteCloser() io.WriteCloser {
	return w.w
}

func (w *testDirectWriteCloser) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	w.t.Error("Buffered relay method is used!")
	return
}

type getBytes interface {
	Bytes() []byte
}

type testReadWriter interface {
	ReadWriter
	getBytes
}

type testReadWriterImpl struct {
	Reader
	Writer
}

func (rw *testReadWriterImpl) FrontHeadroom() int {
	return 0
}

func (rw *testReadWriterImpl) RearHeadroom() int {
	return 0
}

func (rw *testReadWriterImpl) CloseRead() error {
	return rw.Reader.Close()
}

func (rw *testReadWriterImpl) CloseWrite() error {
	return rw.Writer.Close()
}

func (rw *testReadWriterImpl) Close() error {
	crErr := rw.Reader.Close()
	cwErr := rw.Writer.Close()
	if crErr != nil {
		return crErr
	}
	return cwErr
}

func (rw *testReadWriterImpl) Bytes() []byte {
	return rw.Writer.(getBytes).Bytes()
}

func newTestTypicalReadWriter(t *testing.T) (*testReadWriterImpl, []byte) {
	r, b := newTestReader(t)
	return &testReadWriterImpl{
		Reader: r,
		Writer: newTestWriter(t),
	}, b
}

func newTestBigReaderSmallWriter(t *testing.T) (*testReadWriterImpl, []byte) {
	r, b := newTestBigReader(t)
	return &testReadWriterImpl{
		Reader: r,
		Writer: newTestSmallWriter(t),
	}, b
}

type testDirectReadWriter struct {
	*testDirectReadCloser
	*testDirectWriteCloser
}

func (rw *testDirectReadWriter) FrontHeadroom() int {
	return 0
}

func (rw *testDirectReadWriter) RearHeadroom() int {
	return 0
}

func (rw *testDirectReadWriter) CloseRead() error {
	return rw.testDirectReadCloser.Close()
}

func (rw *testDirectReadWriter) CloseWrite() error {
	return rw.testDirectWriteCloser.Close()
}

func (rw *testDirectReadWriter) Close() error {
	crErr := rw.testDirectReadCloser.Close()
	cwErr := rw.testDirectWriteCloser.Close()
	if crErr != nil {
		return crErr
	}
	return cwErr
}

func (rw *testDirectReadWriter) Bytes() []byte {
	return rw.w.Bytes()
}

func newTestDirectReadWriter(t *testing.T) (*testDirectReadWriter, []byte) {
	r, b := newTestDirectReadCloser(t)
	return &testDirectReadWriter{
		testDirectReadCloser:  r,
		testDirectWriteCloser: newTestDirectWriteCloser(t),
	}, b
}

func testTwoWayRelay(t *testing.T, l, r testReadWriter, ldata, rdata []byte) {
	nl2r, nr2l, err := TwoWayRelay(l, r)
	if err != nil {
		t.Error(err)
	}
	if nl2r != 1024 {
		t.Errorf("Expected nl2r: 1024\nGot: %d", nl2r)
	}
	if nr2l != 1024 {
		t.Errorf("Expected nr2l: 1024\nGot: %d", nr2l)
	}

	ldataAfter := l.Bytes()
	rdataAfter := r.Bytes()

	if !bytes.Equal(ldata, rdataAfter) {
		t.Error("l2r copy changed data!")
	}
	if !bytes.Equal(rdata, ldataAfter) {
		t.Error("r2l copy changed data!")
	}
}

func TestTwoWayRelayBuffered(t *testing.T) {
	l, ldata := newTestTypicalReadWriter(t)
	r, rdata := newTestTypicalReadWriter(t)
	testTwoWayRelay(t, l, r, ldata, rdata)
}

func TestTwoWayRelayFallback(t *testing.T) {
	l, ldata := newTestBigReaderSmallWriter(t)
	r, rdata := newTestBigReaderSmallWriter(t)
	testTwoWayRelay(t, l, r, ldata, rdata)
}

func TestTwoWayRelayDirect(t *testing.T) {
	l, ldata := newTestDirectReadWriter(t)
	r, rdata := newTestDirectReadWriter(t)
	testTwoWayRelay(t, l, r, ldata, rdata)
}

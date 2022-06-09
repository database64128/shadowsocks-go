package zerocopy

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

type testReader struct {
	ZeroHeadroom
	t *testing.T
	r *bytes.Reader
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
		r: bytes.NewReader(b),
	}, bcopy
}

func (r *testReader) MinimumPayloadBufferSize() int {
	return 0
}

func (r *testReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	readBuf := b[payloadBufStart : payloadBufStart+payloadBufLen]
	payloadLen, err = r.r.Read(readBuf)
	return
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

func (r *testBigReader) MinimumPayloadBufferSize() int {
	return 64
}

func (r *testBigReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	if len(b) < 64 {
		r.t.Errorf("The read buffer is too small: %d", len(b))
	}
	return r.testReader.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

type testDirectReader struct {
	*testReader
}

func newTestDirectReader(t *testing.T) (*testDirectReader, []byte) {
	r, b := newTestReader(t)
	return &testDirectReader{
		testReader: r,
	}, b
}

func (r *testDirectReader) DirectReader() io.Reader {
	return r.r
}

func (r *testDirectReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	r.t.Error("Buffered relay method is used!")
	return
}

type testWriter struct {
	ZeroHeadroom
	t *testing.T
	w *bytes.Buffer
}

func newTestWriter(t *testing.T) *testWriter {
	b := make([]byte, 0, 1024)
	return &testWriter{
		t: t,
		w: bytes.NewBuffer(b),
	}
}

func (w *testWriter) MaximumPayloadBufferSize() int {
	return 0
}

func (w *testWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	writeBuf := b[payloadStart : payloadStart+payloadLen]
	payloadWritten, err = w.w.Write(writeBuf)
	return
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

func (w *testSmallWriter) MaximumPayloadBufferSize() int {
	return 32
}

func (w *testSmallWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	if len(b) > 32 {
		w.t.Errorf("The write buffer is too big: %d", len(b))
	}
	return w.testWriter.WriteZeroCopy(b, payloadStart, payloadLen)
}

type testDirectWriter struct {
	*testWriter
}

func newTestDirectWriter(t *testing.T) *testDirectWriter {
	return &testDirectWriter{
		testWriter: newTestWriter(t),
	}
}

func (w *testDirectWriter) DirectWriter() io.Writer {
	return w.w
}

func (w *testDirectWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
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
	*testDirectReader
	*testDirectWriter
}

func (rw *testDirectReadWriter) FrontHeadroom() int {
	return 0
}

func (rw *testDirectReadWriter) RearHeadroom() int {
	return 0
}

func (rw *testDirectReadWriter) Bytes() []byte {
	return rw.w.Bytes()
}

func newTestDirectReadWriter(t *testing.T) (*testDirectReadWriter, []byte) {
	r, b := newTestDirectReader(t)
	return &testDirectReadWriter{
		testDirectReader: r,
		testDirectWriter: newTestDirectWriter(t),
	}, b
}

func testReadWriterFunc(t *testing.T, l, r testReadWriter, ldata, rdata []byte) {
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

func TestReadWriter(t *testing.T) {
	l, ldata := newTestTypicalReadWriter(t)
	r, rdata := newTestTypicalReadWriter(t)
	testReadWriterFunc(t, l, r, ldata, rdata)
}

func TestReadWriterFallbackRelay(t *testing.T) {
	l, ldata := newTestBigReaderSmallWriter(t)
	r, rdata := newTestBigReaderSmallWriter(t)
	testReadWriterFunc(t, l, r, ldata, rdata)
}

func TestDirectReadWriter(t *testing.T) {
	l, ldata := newTestDirectReadWriter(t)
	r, rdata := newTestDirectReadWriter(t)
	testReadWriterFunc(t, l, r, ldata, rdata)
}

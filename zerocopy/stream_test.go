package zerocopy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"
)

var errExpectDirect = errors.New("buffered relay method is used")

type testReader struct {
	r *bytes.Reader
}

func newTestReader() (*testReader, []byte) {
	b := make([]byte, 1024)
	rand.Read(b)
	return &testReader{r: bytes.NewReader(b)}, b
}

func (r *testReader) ReaderInfo() ReaderInfo {
	return ReaderInfo{}
}

func (r *testReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	return r.r.Read(b[payloadBufStart : payloadBufStart+payloadBufLen])
}

type testBigReader struct {
	*testReader
}

func newTestBigReader() (*testBigReader, []byte) {
	r, b := newTestReader()
	return &testBigReader{r}, b
}

func (r *testBigReader) ReaderInfo() ReaderInfo {
	return ReaderInfo{MinPayloadBufferSizePerRead: 64}
}

func (r *testBigReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	if len(b) < 64 {
		return 0, fmt.Errorf("read buffer too small: %d", len(b))
	}
	return r.testReader.ReadZeroCopy(b, payloadBufStart, payloadBufLen)
}

type testDirectReader struct {
	*testReader
}

func newTestDirectReadCloser() (*testDirectReader, []byte) {
	r, b := newTestReader()
	return &testDirectReader{r}, b
}

func (r *testDirectReader) DirectReader() io.Reader {
	return r.r
}

func (r *testDirectReader) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	return 0, errExpectDirect
}

type testWriter struct {
	w bytes.Buffer
}

func (w *testWriter) WriterInfo() WriterInfo {
	return WriterInfo{}
}

func (w *testWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	return w.w.Write(b[payloadStart : payloadStart+payloadLen])
}

func (w *testWriter) Bytes() []byte {
	return w.w.Bytes()
}

type testSmallWriter struct {
	testWriter
}

func (w *testSmallWriter) WriterInfo() WriterInfo {
	return WriterInfo{MaxPayloadSizePerWrite: 32}
}

func (w *testSmallWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	if len(b) > 32 {
		return 0, fmt.Errorf("write buffer too big: %d", len(b))
	}
	return w.testWriter.WriteZeroCopy(b, payloadStart, payloadLen)
}

type testDirectWriter struct {
	testWriter
}

func (w *testDirectWriter) DirectWriter() io.Writer {
	return &w.w
}

func (w *testDirectWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	return 0, errExpectDirect
}

type getBytes interface {
	Bytes() []byte
}

type testReadWriter interface {
	ReadWriter
	getBytes
}

type testWriterBytes interface {
	Writer
	getBytes
}

type testReadWriterImpl struct {
	Reader
	testWriterBytes
}

func (rw *testReadWriterImpl) FrontHeadroom() int {
	return 0
}

func (rw *testReadWriterImpl) RearHeadroom() int {
	return 0
}

func (rw *testReadWriterImpl) CloseWrite() error {
	return nil
}

func (rw *testReadWriterImpl) Close() error {
	return nil
}

func newTestTypicalReadWriter() (*testReadWriterImpl, []byte) {
	r, b := newTestReader()
	return &testReadWriterImpl{
		Reader:          r,
		testWriterBytes: &testWriter{},
	}, b
}

func newTestBigReaderSmallWriter() (*testReadWriterImpl, []byte) {
	r, b := newTestBigReader()
	return &testReadWriterImpl{
		Reader:          r,
		testWriterBytes: &testSmallWriter{},
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

func (rw *testDirectReadWriter) CloseWrite() error {
	return nil
}

func (rw *testDirectReadWriter) Close() error {
	return nil
}

func (rw *testDirectReadWriter) Bytes() []byte {
	return rw.w.Bytes()
}

func newTestDirectReadWriter() (*testDirectReadWriter, []byte) {
	r, b := newTestDirectReadCloser()
	return &testDirectReadWriter{
		testDirectReader: r,
		testDirectWriter: &testDirectWriter{},
	}, b
}

func testTwoWayRelay(t *testing.T, l, r testReadWriter, ldata, rdata []byte) {
	nl2r, nr2l, err := TwoWayRelay(l, r)
	if err != nil {
		t.Error(err)
	}
	if nl2r != 1024 {
		t.Errorf("Expected nl2r 1024, got %d", nl2r)
	}
	if nr2l != 1024 {
		t.Errorf("Expected nr2l 1024, got %d", nr2l)
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
	l, ldata := newTestTypicalReadWriter()
	r, rdata := newTestTypicalReadWriter()
	testTwoWayRelay(t, l, r, ldata, rdata)
}

func TestTwoWayRelayFallback(t *testing.T) {
	l, ldata := newTestBigReaderSmallWriter()
	r, rdata := newTestBigReaderSmallWriter()
	testTwoWayRelay(t, l, r, ldata, rdata)
}

func TestTwoWayRelayDirect(t *testing.T) {
	l, ldata := newTestDirectReadWriter()
	r, rdata := newTestDirectReadWriter()
	testTwoWayRelay(t, l, r, ldata, rdata)
}

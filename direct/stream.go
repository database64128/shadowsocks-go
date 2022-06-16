package direct

import (
	"io"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

var (
	_ zerocopy.DirectReadCloser  = (*DirectStreamReadWriter)(nil)
	_ zerocopy.DirectWriteCloser = (*DirectStreamReadWriter)(nil)
)

// DirectStreamReadWriter implements the zerocopy ReadWriter interface and reads/writes everything
// directly from/to the wrapped io.ReadWriter.
type DirectStreamReadWriter struct {
	zerocopy.ZeroHeadroom
	rw zerocopy.DirectReadWriteCloser
}

// MaximumPayloadBufferSize implements the Writer MaximumPayloadBufferSize method.
func (rw *DirectStreamReadWriter) MaximumPayloadBufferSize() int {
	return 0
}

// WriteZeroCopy implements the Writer WriteZeroCopy method.
func (rw *DirectStreamReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	payloadWritten, err = rw.rw.Write(b[payloadStart : payloadStart+payloadLen])
	return
}

// DirectWriteCloser implements the DirectWriteCloser DirectWriteCloser method.
func (rw *DirectStreamReadWriter) DirectWriteCloser() io.WriteCloser {
	return rw.rw
}

// MinimumPayloadBufferSize implements the Reader MinimumPayloadBufferSize method.
func (rw *DirectStreamReadWriter) MinimumPayloadBufferSize() int {
	return 0
}

// ReadZeroCopy implements the Reader ReadZeroCopy method.
func (rw *DirectStreamReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	payloadLen, err = rw.rw.Read(b[payloadBufStart : payloadBufStart+payloadBufLen])
	return
}

// DirectReadCloser implements the DirectReadCloser DirectReadCloser method.
func (rw *DirectStreamReadWriter) DirectReadCloser() io.ReadCloser {
	return rw.rw
}

// CloseWrite implements the ReadWriter CloseWrite method.
func (rw *DirectStreamReadWriter) CloseWrite() error {
	return rw.rw.CloseWrite()
}

// CloseRead implements the ReadWriter CloseRead method.
func (rw *DirectStreamReadWriter) CloseRead() error {
	return rw.rw.CloseRead()
}

// Close implements the ReadWriter Close method.
func (rw *DirectStreamReadWriter) Close() error {
	return rw.rw.Close()
}

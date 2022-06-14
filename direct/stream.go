package direct

import (
	"io"

	"github.com/database64128/shadowsocks-go/zerocopy"
)

// DirectStreamReadWriter implements the zerocopy ReadWriter interface and reads/writes everything
// directly from/to the wrapped io.ReadWriter.
type DirectStreamReadWriter struct {
	zerocopy.ZeroHeadroom
	rw io.ReadWriter
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

// DirectWriter implements the DirectWriter DirectWriter method.
func (rw *DirectStreamReadWriter) DirectWriter() io.Writer {
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

// DirectReader implements the DirectReader DirectReader method.
func (rw *DirectStreamReadWriter) DirectReader() io.Reader {
	return rw.rw
}

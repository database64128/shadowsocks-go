package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// ConnectNonSuccessfulResponseError is returned when the HTTP CONNECT response status code is not 2xx (Successful).
type ConnectNonSuccessfulResponseError struct {
	StatusCode int
}

func newConnectNonSuccessfulResponseError(statusCode int) error {
	return ConnectNonSuccessfulResponseError{StatusCode: statusCode}
}

// Error implements [error.Error].
func (e ConnectNonSuccessfulResponseError) Error() string {
	return fmt.Sprintf("HTTP CONNECT failed with status code %d", e.StatusCode)
}

// NewHttpStreamClientReadWriter writes a HTTP/1.1 CONNECT request to rw and wraps rw into a [zerocopy.ReadWriter] ready for use.
func NewHttpStreamClientReadWriter(rw zerocopy.DirectReadWriteCloser, targetAddr conn.Addr, proxyAuthHeader string) (zerocopy.ReadWriter, error) {
	targetAddress := targetAddr.String()

	// Write CONNECT.
	//
	// Some clients include Proxy-Connection: Keep-Alive in proxy requests.
	// This is discouraged by RFC 9112 as stated in appendix C.2.2, so we don't include it.
	_, err := fmt.Fprintf(rw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: shadowsocks-go/"+shadowsocks.Version+"%s\r\n\r\n", targetAddress, targetAddress, proxyAuthHeader)
	if err != nil {
		return nil, err
	}

	// Read response.
	br := bufio.NewReader(rw)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}

	// Per RFC 9110, any 2xx (Successful) response is considered a success.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newConnectNonSuccessfulResponseError(resp.StatusCode)
	}

	// Check if server spoke first.
	if br.Buffered() > 0 {
		return newDirectReadBufferedStreamReadWriter(rw, br), nil
	}

	return direct.NewDirectStreamReadWriter(rw), nil
}

// directReadBufferedStreamReadWriter is like [direct.DirectStreamReadWriter], but uses a [*bufio.Reader] for reads.
type directReadBufferedStreamReadWriter struct {
	rw zerocopy.DirectReadWriteCloser
	br *bufio.Reader
}

// newDirectReadBufferedStreamReadWriter creates a new [directReadBufferedStreamReadWriter].
func newDirectReadBufferedStreamReadWriter(rw zerocopy.DirectReadWriteCloser, br *bufio.Reader) *directReadBufferedStreamReadWriter {
	return &directReadBufferedStreamReadWriter{rw: rw, br: br}
}

// WriterInfo implements [zerocopy.Writer.WriterInfo].
func (rw *directReadBufferedStreamReadWriter) WriterInfo() zerocopy.WriterInfo {
	return zerocopy.WriterInfo{}
}

// WriteZeroCopy implements [zerocopy.Writer.WriteZeroCopy].
func (rw *directReadBufferedStreamReadWriter) WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error) {
	return rw.rw.Write(b[payloadStart : payloadStart+payloadLen])
}

// DirectWriter implements [zerocopy.DirectWriter.DirectWriter].
func (rw *directReadBufferedStreamReadWriter) DirectWriter() io.Writer {
	return rw.rw
}

// ReaderInfo implements [zerocopy.Reader.ReaderInfo].
func (rw *directReadBufferedStreamReadWriter) ReaderInfo() zerocopy.ReaderInfo {
	return zerocopy.ReaderInfo{}
}

// ReadZeroCopy implements [zerocopy.Reader.ReadZeroCopy].
func (rw *directReadBufferedStreamReadWriter) ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error) {
	return rw.br.Read(b[payloadBufStart : payloadBufStart+payloadBufLen])
}

// DirectReader implements [zerocopy.DirectReader.DirectReader].
func (rw *directReadBufferedStreamReadWriter) DirectReader() io.Reader {
	return rw.br
}

// CloseWrite implements [zerocopy.ReadWriter.CloseWrite].
func (rw *directReadBufferedStreamReadWriter) CloseWrite() error {
	return rw.rw.CloseWrite()
}

// Close implements [zerocopy.ReadWriter.Close].
func (rw *directReadBufferedStreamReadWriter) Close() error {
	return rw.rw.Close()
}

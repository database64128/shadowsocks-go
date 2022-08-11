package direct

import (
	"io"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go"
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

// MaxPayloadSizePerWrite implements the Writer MaxPayloadSizePerWrite method.
func (rw *DirectStreamReadWriter) MaxPayloadSizePerWrite() int {
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

// MinPayloadBufferSizePerRead implements the Reader MinPayloadBufferSizePerRead method.
func (rw *DirectStreamReadWriter) MinPayloadBufferSizePerRead() int {
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

// NewDirectStreamReadWriter returns a ReadWriter that passes all reads and writes directly to the underlying stream.
func NewDirectStreamReadWriter(rw zerocopy.DirectReadWriteCloser) *DirectStreamReadWriter {
	return &DirectStreamReadWriter{
		rw: rw,
	}
}

// NewShadowsocksNoneStreamClientReadWriter creates a ReadWriter that acts as a Shadowsocks none method client.
func NewShadowsocksNoneStreamClientReadWriter(rw zerocopy.DirectReadWriteCloser, targetAddr conn.Addr, payload []byte) (*DirectStreamReadWriter, error) {
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	writeBuf := make([]byte, targetAddrLen+len(payload))
	socks5.WriteAddrFromConnAddr(writeBuf, targetAddr)
	copy(writeBuf[targetAddrLen:], payload)
	if _, err := rw.Write(writeBuf); err != nil {
		return nil, err
	}
	return &DirectStreamReadWriter{rw: rw}, nil
}

// NewShadowsocksNoneStreamServerReadWriter creates a ReadWriter that acts as a Shadowsocks none method server.
func NewShadowsocksNoneStreamServerReadWriter(rw zerocopy.DirectReadWriteCloser) (*DirectStreamReadWriter, conn.Addr, error) {
	addr, err := socks5.ConnAddrFromReader(rw)
	if err != nil {
		return nil, addr, err
	}
	return &DirectStreamReadWriter{rw: rw}, addr, nil
}

// NewSocks5StreamClientReadWriter writes a SOCKS5 CONNECT request to rw and wraps rw into a ReadWriter ready for use.
func NewSocks5StreamClientReadWriter(rw zerocopy.DirectReadWriteCloser, targetAddr conn.Addr) (*DirectStreamReadWriter, error) {
	if err := socks5.ClientConnect(rw, targetAddr); err != nil {
		return nil, err
	}
	return &DirectStreamReadWriter{rw: rw}, nil
}

// NewSocks5StreamServerReadWriter handles a SOCKS5 request from rw and wraps rw into a ReadWriter ready for use.
// conn must be provided when UDP is enabled.
func NewSocks5StreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, enableTCP, enableUDP bool, conn tfo.Conn) (dsrw *DirectStreamReadWriter, addr conn.Addr, err error) {
	addr, err = socks5.ServerAccept(rw, enableTCP, enableUDP, conn)
	if err == nil {
		dsrw = &DirectStreamReadWriter{
			rw: rw,
		}
	}
	return
}

package direct

import (
	"context"
	"io"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

var (
	_ zerocopy.DirectReader = (*DirectStreamReadWriter)(nil)
	_ zerocopy.DirectWriter = (*DirectStreamReadWriter)(nil)
)

// DirectStreamReadWriter implements the zerocopy ReadWriter interface and reads/writes everything
// directly from/to the wrapped io.ReadWriter.
type DirectStreamReadWriter struct {
	rw zerocopy.DirectReadWriteCloser
}

// WriterInfo implements the Writer WriterInfo method.
func (rw *DirectStreamReadWriter) WriterInfo() zerocopy.WriterInfo {
	return zerocopy.WriterInfo{}
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

// ReaderInfo implements the Reader ReaderInfo method.
func (rw *DirectStreamReadWriter) ReaderInfo() zerocopy.ReaderInfo {
	return zerocopy.ReaderInfo{}
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
func NewShadowsocksNoneStreamClientReadWriter(ctx context.Context, rwo zerocopy.DirectReadWriteCloserOpener, targetAddr conn.Addr, payload []byte) (*DirectStreamReadWriter, zerocopy.DirectReadWriteCloser, error) {
	targetAddrLen := socks5.LengthOfAddrFromConnAddr(targetAddr)
	writeBuf := make([]byte, targetAddrLen+len(payload))
	socks5.WriteAddrFromConnAddr(writeBuf, targetAddr)
	copy(writeBuf[targetAddrLen:], payload)
	rawRW, err := rwo.Open(ctx, writeBuf)
	if err != nil {
		return nil, nil, err
	}
	return &DirectStreamReadWriter{rw: rawRW}, rawRW, nil
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

// NewSocks5AuthStreamClientReadWriter is like [NewSocks5StreamClientReadWriter], but uses username/password authentication.
func NewSocks5AuthStreamClientReadWriter(rw zerocopy.DirectReadWriteCloser, authMsg []byte, targetAddr conn.Addr) (*DirectStreamReadWriter, error) {
	if err := socks5.ClientConnectUsernamePassword(rw, authMsg, targetAddr); err != nil {
		return nil, err
	}
	return &DirectStreamReadWriter{rw: rw}, nil
}

// NewSocks5StreamServerReadWriter handles a SOCKS5 request from rw and wraps rw into a ReadWriter ready for use.
//
// When UDP is enabled, rw must be a [*net.TCPConn].
func NewSocks5StreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, enableTCP, enableUDP bool) (dsrw *DirectStreamReadWriter, addr conn.Addr, err error) {
	pc, addr, err := socks5.ServerAccept(rw.(netio.Conn), zap.L(), enableTCP, enableUDP)
	if err != nil {
		return nil, addr, err
	}
	if pc != nil {
		if _, err = pc.Proceed(); err != nil {
			return nil, addr, err
		}
	}
	return &DirectStreamReadWriter{rw: rw}, addr, nil
}

// NewSocks5AuthStreamServerReadWriter is like [NewSocks5StreamServerReadWriter], but uses username/password authentication.
func NewSocks5AuthStreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, userInfoByUsername map[string]socks5.UserInfo, enableTCP, enableUDP bool) (dsrw *DirectStreamReadWriter, addr conn.Addr, username string, err error) {
	pc, addr, username, err := socks5.ServerAcceptUsernamePassword(rw.(netio.Conn), zap.L(), userInfoByUsername, enableTCP, enableUDP)
	if err != nil {
		return nil, addr, username, err
	}
	if pc != nil {
		if _, err = pc.Proceed(); err != nil {
			return nil, addr, username, err
		}
	}
	return &DirectStreamReadWriter{rw: rw}, addr, username, nil
}

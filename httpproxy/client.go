package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
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

// ClientConnect writes a HTTP/1.1 CONNECT request to rw and returns the encapsulated stream or an error.
func ClientConnect(rw netio.Conn, targetAddr conn.Addr, proxyAuthHeader string) (netio.Conn, error) {
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
		return newReadBufferedNetioConn(rw, br), nil
	}

	return rw, nil
}

// readBufferedNetioConn embeds a [netio.Conn], but redirects reads to a paired [*bufio.Reader].
type readBufferedNetioConn struct {
	netio.Conn
	br *bufio.Reader
}

// Read implements [netio.Conn.Read].
func (c readBufferedNetioConn) Read(b []byte) (int, error) {
	// Only read from the buffered reader if it has unread data.
	// This prevents the buffered reader from seeing and remembering [os.ErrDeadlineExceeded] errors.
	if c.br.Buffered() > 0 {
		return c.br.Read(b)
	}
	return c.Conn.Read(b)
}

// WriteTo implements [io.WriterTo].
func (c readBufferedNetioConn) WriteTo(w io.Writer) (int64, error) {
	// No need to worry about [os.ErrDeadlineExceeded] here, as
	// the implementation does not care about previous read errors.
	return c.br.WriteTo(w)
}

// readBufferedNetioConnReaderFrom is a [readBufferedNetioConn] that implements [io.ReaderFrom].
type readBufferedNetioConnReaderFrom struct {
	readBufferedNetioConn
}

// ReadFrom implements [io.ReaderFrom].
func (c readBufferedNetioConnReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	return c.Conn.(io.ReaderFrom).ReadFrom(r)
}

// newReadBufferedNetioConn returns c with reads redirected to br.
func newReadBufferedNetioConn(c netio.Conn, br *bufio.Reader) netio.Conn {
	bc := readBufferedNetioConn{Conn: c, br: br}
	if _, ok := c.(io.ReaderFrom); ok {
		return readBufferedNetioConnReaderFrom{bc}
	}
	return bc
}

package httpproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"go.uber.org/zap"
)

// FailedAuthAttemptsError is returned when the client fails to authenticate itself during the lifetime of the connection.
type FailedAuthAttemptsError struct {
	// Attempts is the number of failed attempts.
	Attempts int
}

func newFailedAuthAttemptsError(attempts int) error {
	return FailedAuthAttemptsError{Attempts: attempts}
}

// Error implements [error.Error].
func (e FailedAuthAttemptsError) Error() string {
	return fmt.Sprintf("%d failed authentication attempt(s)", e.Attempts)
}

// ServerHandle handles an HTTP request from rw.
func ServerHandle(rw netio.Conn, logger *zap.Logger, usernameByToken map[string]string) (pc netio.PendingConn, targetAddr conn.Addr, username string, err error) {
	var (
		req                *http.Request
		failedAuthAttempts int
	)

	rwbr := bufio.NewReader(rw)

	for {
		req, err = http.ReadRequest(rwbr)
		if err != nil {
			if failedAuthAttempts > 0 {
				return nil, conn.Addr{}, "", fmt.Errorf("failed to read HTTP request after %w: %w", newFailedAuthAttemptsError(failedAuthAttempts), err)
			}
			return nil, conn.Addr{}, "", fmt.Errorf("failed to read HTTP request: %w", err)
		}

		if usernameByToken == nil {
			break
		}

		var ok bool
		username, ok = serverHandleBasicAuth(req.Header, usernameByToken)
		if ok {
			break
		}

		failedAuthAttempts++

		if ce := logger.Check(zap.DebugLevel, "Sending 407 Proxy Authentication Required response"); ce != nil {
			ce.Write(
				zap.String("proto", req.Proto),
				zap.String("method", req.Method),
				zap.String("url", req.RequestURI),
				zap.String("host", req.Host),
				zap.Int64("contentLength", req.ContentLength),
				zap.Bool("close", req.Close),
				zap.Int("failedAuthAttempts", failedAuthAttempts),
			)
		}

		if err = send407(rw); err != nil {
			return nil, conn.Addr{}, "", fmt.Errorf("failed to send 407 Proxy Authentication Required response after %w: %w", newFailedAuthAttemptsError(failedAuthAttempts), err)
		}

		if req.Close {
			return nil, conn.Addr{}, "", newFailedAuthAttemptsError(failedAuthAttempts)
		}
	}

	if ce := logger.Check(zap.DebugLevel, "Received initial HTTP request"); ce != nil {
		ce.Write(
			zap.String("proto", req.Proto),
			zap.String("method", req.Method),
			zap.String("url", req.RequestURI),
			zap.String("host", req.Host),
			zap.Int64("contentLength", req.ContentLength),
			zap.Bool("close", req.Close),
		)
	}

	// Fast-track CONNECT.
	if req.Method == http.MethodConnect {
		// RFC 9110 section 9.3.6 says:
		//
		//	CONNECT uses a special form of request target, unique to this method, consisting of only
		//	the host and port number of the tunnel destination, separated by a colon. There is no
		//	default port; a client MUST send the port number even if the CONNECT request is based on
		//	a URI reference that contains an authority component with an elided port (Section 4.1).
		//
		//	A server MUST reject a CONNECT request that targets an empty or invalid port number,
		//	typically by responding with a 400 (Bad Request) status code.
		targetAddr, err = conn.ParseAddr(req.RequestURI)
		if err != nil {
			_ = send400(rw)
			return nil, conn.Addr{}, username, fmt.Errorf("failed to parse request target: %w", err)
		}
		return newServerConnectPendingConn(rw), targetAddr, username, nil
	}

	// Host -> targetAddr
	targetAddr, err = hostHeaderToAddr(req.Host)
	if err != nil {
		_ = send400(rw)
		return nil, conn.Addr{}, username, fmt.Errorf("failed to parse host header: %w", err)
	}

	return newServerNonConnectPendingConn(rw, logger, rwbr, req), targetAddr, username, nil
}

// serverConnectPendingConn wraps a [netio.Conn] from which a CONNECT request was received.
//
// serverConnectPendingConn implements [netio.PendingConn].
type serverConnectPendingConn struct {
	inner netio.Conn
}

// newServerConnectPendingConn returns the connection wrapped as a [netio.PendingConn].
func newServerConnectPendingConn(c netio.Conn) netio.PendingConn {
	return serverConnectPendingConn{inner: c}
}

// Proceed implements [netio.PendingConn.Proceed].
func (c serverConnectPendingConn) Proceed() (netio.Conn, error) {
	if err := send200(c.inner); err != nil {
		return nil, fmt.Errorf("failed to send 200 OK response: %w", err)
	}
	return c.inner, nil
}

// Abort implements [netio.PendingConn.Abort].
func (c serverConnectPendingConn) Abort(_ conn.DialResult) error {
	if err := send502(c.inner); err != nil {
		return fmt.Errorf("failed to send 502 Bad Gateway response: %w", err)
	}
	return nil
}

// serverNonConnectPendingConn wraps a [netio.Conn] from which a non-CONNECT request was received.
//
// serverNonConnectPendingConn implements [netio.PendingConn].
type serverNonConnectPendingConn struct {
	rw     netio.Conn
	logger *zap.Logger
	rwbr   *bufio.Reader
	req    *http.Request
}

// newServerNonConnectPendingConn returns the connection wrapped as a [netio.PendingConn].
func newServerNonConnectPendingConn(rw netio.Conn, logger *zap.Logger, rwbr *bufio.Reader, req *http.Request) netio.PendingConn {
	return serverNonConnectPendingConn{
		rw:     rw,
		logger: logger,
		rwbr:   rwbr,
		req:    req,
	}
}

// Proceed implements [netio.PendingConn.Proceed].
func (c serverNonConnectPendingConn) Proceed() (netio.Conn, error) {
	// Set up pipes.
	pl, pr := netio.NewPipe()

	// Spin up separate request and response forwarding goroutines.
	// This is necessary for handling 1xx informational responses, and allows pipelining.
	go func() {
		defer c.rw.Close()

		plbr := bufio.NewReader(pl)
		plbw := bufio.NewWriter(pl)
		rwbw := bufio.NewWriter(c.rw)
		rwbwpcw := newPipeClosingWriter(rwbw, pl)
		reqCh := make(chan *http.Request, 16) // allow pipelining up to 16 requests
		respDone := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			err := serverForwardRequests(c.req, reqCh, respDone, plbw, c.rwbr, c.logger)
			pl.CloseWriteWithError(err)
			close(reqCh)
		}()

		err := serverForwardResponses(reqCh, plbr, c.rw, rwbw, rwbwpcw, c.logger)
		pl.CloseReadWithError(err)
		_ = c.rw.CloseWrite()
		close(respDone)

		wg.Wait()
	}()

	return pr, nil
}

// Abort implements [netio.PendingConn.Abort].
func (c serverNonConnectPendingConn) Abort(_ conn.DialResult) error {
	if err := send502(c.rw); err != nil {
		return fmt.Errorf("failed to send 502 Bad Gateway response: %w", err)
	}
	return nil
}

func serverHandleBasicAuth(header http.Header, usernameByToken map[string]string) (string, bool) {
	for _, creds := range header["Proxy-Authorization"] {
		const prefix = "Basic "
		if len(creds) > len(prefix) &&
			(creds[0] == 'B' || creds[0] == 'b') &&
			(creds[1] == 'a' || creds[1] == 'A') &&
			(creds[2] == 's' || creds[2] == 'S') &&
			(creds[3] == 'i' || creds[3] == 'I') &&
			(creds[4] == 'c' || creds[4] == 'C') &&
			creds[5] == ' ' {
			username, ok := usernameByToken[creds[len(prefix):]]
			return username, ok
		}
	}

	return "", false
}

func serverForwardRequests(
	req *http.Request,
	reqCh chan<- *http.Request,
	respDone <-chan struct{},
	plbw *bufio.Writer,
	rwbr *bufio.Reader,
	logger *zap.Logger,
) (err error) {
	// The current implementation only supports a fixed destination host.
	fixedHost := req.Host

	for {
		// Remove hop-by-hop header and trailer fields.
		removeConnectionSpecificFields(req.Header, req.Trailer)

		// Remove the Upgrade header field from the request.
		// In practice, browsers seem to only use SOCKS5 proxies and HTTP CONNECT for
		// WebSocket connections. It's not worth the extra complexity to support something
		// no one uses.
		delete(req.Header, "Upgrade")

		// Notify the response forwarding routine about the request before writing it out,
		// so that a received 1xx informational response can be forwarded back to the client
		// in time, unblocking the write.
		select {
		case reqCh <- req:
		case <-respDone:
		}

		// Write request.
		if err = req.Write(plbw); err != nil {
			return fmt.Errorf("failed to write HTTP request: %w", err)
		}

		// Flush request.
		if err = plbw.Flush(); err != nil {
			return fmt.Errorf("failed to flush HTTP request: %w", err)
		}

		// No need to check req.Close here because http.ReadRequest will naturally
		// fail with io.EOF when the client shuts down further writes.

		// Read request.
		req, err = http.ReadRequest(rwbr)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read HTTP request: %w", err)
		}

		if ce := logger.Check(zap.DebugLevel, "Received subsequent HTTP request"); ce != nil {
			ce.Write(
				zap.String("proto", req.Proto),
				zap.String("method", req.Method),
				zap.String("url", req.RequestURI),
				zap.String("host", req.Host),
				zap.String("fixedHost", fixedHost),
				zap.Int64("contentLength", req.ContentLength),
				zap.Bool("close", req.Close),
			)
		}

		// Close the proxy connection if the destination host changes.
		// This is allowed, according to RFC 9112 section 9.5:
		//
		//	A client, server, or proxy MAY close the transport connection at any time.
		//	For example, a client might have started to send a new request at the same
		//	time that the server has decided to close the "idle" connection. From the
		//	server's point of view, the connection is being closed while it was idle,
		//	but from the client's point of view, a request is in progress.

		// According to RFC 9110 section 3.3, a CONNECT request can occur at any time,
		// not just in the first message on a connection.
		//
		// In practice, no client is known to do this. And a hypothetical client doing
		// it would likely be doing so to establish a tunnel to a different host,
		// which we cannot handle and have to close the connection anyway.
		if req.Method == http.MethodConnect {
			logger.Debug("Subsequent HTTP request method is CONNECT, closing connection")
			return nil
		}

		if req.Host != fixedHost {
			if ce := logger.Check(zap.DebugLevel, "Host header changed, closing connection"); ce != nil {
				ce.Write(
					zap.String("oldHost", fixedHost),
					zap.String("newHost", req.Host),
				)
			}
			return nil
		}
	}
}

var errPayloadAfterFinalResponse = errors.New("payload after final response")

func serverForwardResponses(
	reqCh <-chan *http.Request,
	plbr *bufio.Reader,
	rw netio.ReadWriter,
	rwbw *bufio.Writer,
	rwbwpcw *pipeClosingWriter,
	logger *zap.Logger,
) error {
	for {
		// Use Peek to monitor the remote connection, so that we can close the proxy connection
		// as soon as the remote server closes the connection.
		//
		// If the client sees EOF right after sending a request, it will retry the request.
		// Do not send a 502 Bad Gateway response. It will only confuse the client.
		if _, err := plbr.Peek(1); err != nil {
			if err == io.EOF {
				return nil
			}
			logger.Warn("Failed to peek HTTP response", zap.Error(err))
			return fmt.Errorf("failed to peek HTTP response: %w", err)
		}

		req, ok := <-reqCh
		if !ok {
			return errPayloadAfterFinalResponse
		}

		for {
			// Read response.
			resp, err := http.ReadResponse(plbr, req)
			if err != nil {
				logger.Warn("Failed to read HTTP response",
					zap.String("reqProto", req.Proto),
					zap.String("reqMethod", req.Method),
					zap.String("reqURL", req.RequestURI),
					zap.String("reqHost", req.Host),
					zap.Int64("reqContentLength", req.ContentLength),
					zap.Bool("reqClose", req.Close),
					zap.Error(err),
				)
				_ = send502(rw)
				return fmt.Errorf("failed to read HTTP response: %w", err)
			}

			if ce := logger.Check(zap.DebugLevel, "Received HTTP response"); ce != nil {
				ce.Write(
					zap.String("reqProto", req.Proto),
					zap.String("reqMethod", req.Method),
					zap.String("reqURL", req.RequestURI),
					zap.String("reqHost", req.Host),
					zap.Int64("reqContentLength", req.ContentLength),
					zap.Bool("reqClose", req.Close),
					zap.String("respProto", resp.Proto),
					zap.String("respStatus", resp.Status),
					zap.Int64("respContentLength", resp.ContentLength),
					zap.Bool("respClose", resp.Close),
				)
			}

			// Add Connection: close if response is 301, 302, or 307,
			// and Location points to a different host.
			switch resp.StatusCode {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect:
				location := resp.Header["Location"]

				if ce := logger.Check(zap.DebugLevel, "Checking HTTP 3xx response Location header"); ce != nil {
					ce.Write(
						zap.String("reqProto", req.Proto),
						zap.String("reqMethod", req.Method),
						zap.String("reqURL", req.RequestURI),
						zap.String("reqHost", req.Host),
						zap.String("respProto", resp.Proto),
						zap.String("respStatus", resp.Status),
						zap.Strings("respLocation", location),
					)
				}

				if len(location) != 1 {
					break
				}

				url, err := url.Parse(location[0])
				if err != nil {
					break
				}

				switch url.Host {
				case req.Host, "":
				default:
					resp.Close = true
				}
			}

			// Remove hop-by-hop header and trailer fields.
			removeConnectionSpecificFields(resp.Header, resp.Trailer)

			// Write response.
			//
			// The Write method always drains the response body, even when the destination writer returns an error.
			// This can become a problem when the response body is large or unbounded in size.
			// A typical scenario is when the client downloads a large file but aborts the connection midway.
			// The Write call will block until the entire file is downloaded, which is a total waste of resources.
			// To mitigate this, we wrap the destination writer in a [*pipeClosingWriter] that stops further reads on write error.
			//
			// If we migrate to using [*http.Client], [*pipeClosingWriter] needs to be updated to cancel the request context instead.
			if err = resp.Write(rwbwpcw); err != nil {
				logger.Warn("Failed to write HTTP response",
					zap.String("reqProto", req.Proto),
					zap.String("reqMethod", req.Method),
					zap.String("reqURL", req.RequestURI),
					zap.String("reqHost", req.Host),
					zap.Int64("reqContentLength", req.ContentLength),
					zap.Bool("reqClose", req.Close),
					zap.String("respProto", resp.Proto),
					zap.String("respStatus", resp.Status),
					zap.Int64("respContentLength", resp.ContentLength),
					zap.Bool("respClose", resp.Close),
					zap.Error(err),
				)
				return fmt.Errorf("failed to write HTTP response: %w", err)
			}

			// Flush response.
			if err = rwbw.Flush(); err != nil {
				logger.Warn("Failed to flush HTTP response",
					zap.String("reqProto", req.Proto),
					zap.String("reqMethod", req.Method),
					zap.String("reqURL", req.RequestURI),
					zap.String("reqHost", req.Host),
					zap.Int64("reqContentLength", req.ContentLength),
					zap.Bool("reqClose", req.Close),
					zap.String("respProto", resp.Proto),
					zap.String("respStatus", resp.Status),
					zap.Int64("respContentLength", resp.ContentLength),
					zap.Bool("respClose", resp.Close),
					zap.Error(err),
				)
				return fmt.Errorf("failed to flush HTTP response: %w", err)
			}

			// Stop forwarding if either the client or server indicates that the connection should be closed.
			//
			// RFC 9112 section 9.6 says:
			//
			//	The server SHOULD send a "close" connection option in its final response on that connection.
			//
			// It's not a "MUST", so we check both.
			if req.Close || resp.Close {
				return errPayloadAfterFinalResponse
			}

			// If the response is final (not 1xx informational), we are done.
			if resp.StatusCode >= http.StatusOK {
				break
			}
		}
	}
}

var errEmptyHostHeader = errors.New("empty host header")

// hostHeaderToAddr parses the Host header into an address.
//
// Host may be in any of the following forms:
//   - example.com
//   - example.com:443
//   - 1.1.1.1
//   - 1.1.1.1:443
//   - [2606:4700:4700::1111]
//   - [2606:4700:4700::1111]:443
func hostHeaderToAddr(host string) (conn.Addr, error) {
	switch {
	case len(host) == 0:
		return conn.Addr{}, errEmptyHostHeader
	case strings.IndexByte(host, ':') == -1:
		return conn.AddrFromHostPort(host, 80)
	case host[0] == '[' && host[len(host)-1] == ']':
		return conn.AddrFromHostPort(host[1:len(host)-1], 80)
	default:
		return conn.ParseAddr(host)
	}
}

func send200(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return err
}

func send400(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
	return err
}

func send407(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"shadowsocks-go\", charset=\"UTF-8\"\r\n\r\n"))
	return err
}

func send502(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
	return err
}

// removeConnectionSpecificFields removes hop-by-hop header and trailer fields,
// including but not limited to those specified in Connection.
//
// The Upgrade header field is not removed, as it is allowed to do something like:
//
//	Upgrade: HTTP/3.0
func removeConnectionSpecificFields(header, trailer http.Header) {
	for _, opts := range header["Connection"] {
		var (
			opt   string
			found bool
		)

		for {
			opt, opts, found = strings.Cut(opts, ",")
			opt = strings.TrimSpace(opt)
			canOpt := http.CanonicalHeaderKey(opt)

			switch canOpt {
			case "Close", "Upgrade":
			default:
				delete(header, canOpt)
				delete(trailer, canOpt)
			}

			if !found {
				break
			}
		}
	}

	delete(header, "Connection")
	delete(header, "Proxy-Connection")
	delete(header, "Keep-Alive")
	delete(header, "Te")
	delete(header, "Transfer-Encoding")

	delete(header, "Proxy-Authenticate")
	delete(header, "Proxy-Authorization")
	delete(header, "Proxy-Authentication-Info")
}

// pipeClosingWriter passes writes to the underlying [*bufio.Writer] and closes the [*netio.PipeConn] on error.
type pipeClosingWriter struct {
	w *bufio.Writer
	p *netio.PipeConn
}

// newPipeClosingWriter returns a new [pipeClosingWriter].
func newPipeClosingWriter(w *bufio.Writer, p *netio.PipeConn) *pipeClosingWriter {
	return &pipeClosingWriter{
		w: w,
		p: p,
	}
}

// Write implements [io.Writer].
func (w *pipeClosingWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return n, err
}

// WriteByte implements [io.ByteWriter].
func (w *pipeClosingWriter) WriteByte(c byte) error {
	err := w.w.WriteByte(c)
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return err
}

// WriteRune writes a single Unicode code point, returning
// the number of bytes written and any error.
func (w *pipeClosingWriter) WriteRune(r rune) (int, error) {
	n, err := w.w.WriteRune(r)
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return n, err
}

// WriteString implements [io.StringWriter].
func (w *pipeClosingWriter) WriteString(s string) (int, error) {
	n, err := w.w.WriteString(s)
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return n, err
}

// ReadFrom implements [io.ReaderFrom].
func (w *pipeClosingWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := w.w.ReadFrom(r)
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return n, err
}

// Flush writes any buffered data to the underlying [io.Writer].
func (w *pipeClosingWriter) Flush() error {
	err := w.w.Flush()
	if err != nil {
		w.p.CloseReadWithError(err)
	}
	return err
}

package http

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
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// NewHttpStreamServerReadWriter handles a HTTP request from rw and wraps rw into a ReadWriter ready for use.
func NewHttpStreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, logger *zap.Logger) (*direct.DirectStreamReadWriter, conn.Addr, error) {
	rwbr := bufio.NewReader(rw)
	req, err := http.ReadRequest(rwbr)
	if err != nil {
		return nil, conn.Addr{}, err
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

	// Host -> targetAddr
	targetAddr, err := hostHeaderToAddr(req.Host)
	if err != nil {
		_ = send400(rw)
		return nil, conn.Addr{}, err
	}

	// Fast-track CONNECT.
	if req.Method == http.MethodConnect {
		if err = send200(rw); err != nil {
			return nil, conn.Addr{}, err
		}
		return direct.NewDirectStreamReadWriter(rw), targetAddr, nil
	}

	// Set up pipes.
	pl, pr := pipe.NewDuplexPipe()

	// Spin up separate request and response forwarding goroutines.
	// This is necessary for handling 100 Continue responses, and allows pipelining.
	go func() {
		defer func() {
			_ = pl.Close()
			_ = rw.Close()
		}()

		plbr := bufio.NewReader(pl)
		plbw := bufio.NewWriter(pl)
		rwbw := bufio.NewWriter(rw)
		rwbwpcw := newPipeClosingWriter(rwbw, pl)
		reqCh := make(chan *http.Request, 16) // allow pipelining up to 16 requests

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			err := serverForwardRequests(targetAddr, req, reqCh, pl, plbw, rw, rwbr, logger)
			pl.CloseWriteWithError(err)
		}()

		serverForwardResponses(reqCh, plbr, rw, rwbw, rwbwpcw, logger)

		wg.Wait()
	}()

	// Wrap pr into a direct stream ReadWriter.
	return direct.NewDirectStreamReadWriter(pr), targetAddr, nil
}

func serverForwardRequests(
	targetAddr conn.Addr,
	req *http.Request,
	reqCh chan<- *http.Request,
	pl *pipe.DuplexPipeEnd,
	plbw *bufio.Writer,
	rw zerocopy.DirectReadWriteCloser,
	rwbr *bufio.Reader,
	logger *zap.Logger,
) (err error) {
	defer close(reqCh)

	// The current implementation only supports a fixed destination host.
	fixedHost := req.Host

	for {
		// Remove hop-by-hop header and trailer fields.
		removeConnectionSpecificFields(req.Header, req.Trailer)

		// Notify the response forwarding routine about the request before writing it out,
		// so that a received 100 Continue response can be forwarded back to the client
		// in time, unblocking the write.
		reqCh <- req

		// Write request.
		if err = req.Write(plbw); err != nil {
			return fmt.Errorf("failed to write HTTP request: %w", err)
		}

		// Flush request.
		if err = plbw.Flush(); err != nil {
			return fmt.Errorf("failed to flush HTTP request: %w", err)
		}

		// We might want to look at the Upgrade header here and handle it accordingly.
		// In practice, browsers seem to only use SOCKS5 proxies and HTTP CONNECT for
		// WebSocket connections, so we hold off on the extra complexity for now.

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
		// not just in the first message on a connection. Although no client is known to
		// do this, we handle it with best effort.
		if req.Method == http.MethodConnect {
			// The Host header in a CONNECT request includes the port number,
			// whereas in other requests the port number is usually omitted if it's 80.
			// Therefore, parse and compare as a socket address.
			newTargetAddr, err := hostHeaderToAddr(req.Host)
			if err != nil {
				_ = send400(pl)
				return err
			}

			if !newTargetAddr.Equals(targetAddr) {
				if ce := logger.Check(zap.DebugLevel, "CONNECT request to different host, closing connection"); ce != nil {
					ce.Write(
						zap.String("oldHost", fixedHost),
						zap.String("newHost", req.Host),
					)
				}
				return nil
			}

			if err = send200(pl); err != nil {
				return fmt.Errorf("failed to send 200 OK response: %w", err)
			}

			_, _, err = zerocopy.DirectTwoWayRelay(rw, pl)
			return err
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

func serverForwardResponses(reqCh <-chan *http.Request, plbr *bufio.Reader, rw zerocopy.DirectReadWriteCloser, rwbw *bufio.Writer, rwbwpcw *pipeClosingWriter, logger *zap.Logger) {
	defer rw.CloseWrite()

	for req := range reqCh {
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
				return
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
				return
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
				return
			}

			// Stop forwarding if either the client or server indicates that the connection should be closed.
			//
			// RFC 9112 section 9.6 says:
			//
			//	The server SHOULD send a "close" connection option in its final response on that connection.
			//
			// It's not a "MUST", so we check both.
			if req.Close || resp.Close {
				return
			}

			// 100 Continue is not the final response.
			if resp.StatusCode != http.StatusContinue {
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

func send502(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
	return err
}

// removeConnectionSpecificFields removes hop-by-hop header and trailer fields,
// including but not limited to those specified in Connection.
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
}

// pipeClosingWriter passes writes to the underlying [io.Writer] and closes the [*pipe.DuplexPipeEnd] on error.
type pipeClosingWriter struct {
	w io.Writer
	p *pipe.DuplexPipeEnd
}

// newPipeClosingWriter returns a new [pipeClosingWriter].
func newPipeClosingWriter(w io.Writer, p *pipe.DuplexPipeEnd) *pipeClosingWriter {
	return &pipeClosingWriter{
		w: w,
		p: p,
	}
}

// Write implements [io.Writer.Write].
func (w *pipeClosingWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err != nil {
		w.p.CloseWithError(err)
	}
	return n, err
}

package http

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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

	// Host -> targetAddr
	targetAddr, err := hostHeaderToAddr(req.Host)
	if err != nil {
		_ = send400(rw)
		return nil, conn.Addr{}, err
	}

	// Fast-track CONNECT.
	if req.Method == http.MethodConnect {
		if _, err = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nDate: %s\r\n\r\n", time.Now().UTC().Format(http.TimeFormat)); err != nil {
			return nil, conn.Addr{}, err
		}
		return direct.NewDirectStreamReadWriter(rw), targetAddr, nil
	}

	// Set up pipes.
	pl, pr := pipe.NewDuplexPipe()

	// Spin up a goroutine to write processed requests to pl
	// and read responses from pl.
	go func() {
		var rerr, werr error

		plbr := bufio.NewReader(pl)
		plbw := bufio.NewWriter(pl)
		rwbw := bufio.NewWriter(rw)

		// The current implementation only supports a fixed destination host.
		fixedHost := req.Host

		for {
			// Delete hop-by-hop headers specified in Connection.
			connectionHeader := req.Header["Connection"]
			for i := range connectionHeader {
				req.Header.Del(connectionHeader[i])
			}
			delete(req.Header, "Connection")

			delete(req.Header, "Proxy-Connection")

			if ce := logger.Check(zap.DebugLevel, "Writing HTTP request"); ce != nil {
				ce.Write(
					zap.String("proto", req.Proto),
					zap.String("method", req.Method),
					zap.String("url", req.RequestURI),
				)
			}

			// Write request.
			if werr = req.Write(plbw); werr != nil {
				werr = fmt.Errorf("failed to write HTTP request: %w", werr)
				_ = send502(rw)
				break
			}

			// Flush request.
			if werr = plbw.Flush(); werr != nil {
				werr = fmt.Errorf("failed to flush HTTP request: %w", werr)
				_ = send502(rw)
				break
			}

			var resp *http.Response

			// Read response.
			resp, rerr = http.ReadResponse(plbr, req)
			if rerr != nil {
				rerr = fmt.Errorf("failed to read HTTP response: %w", rerr)
				_ = send502(rw)
				break
			}

			// Add Connection: close if response is 301, 302, or 307,
			// and Location points to a different host.
			switch resp.StatusCode {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect:
				location := resp.Header["Location"]

				if ce := logger.Check(zap.DebugLevel, "Checking HTTP 3xx response Location header"); ce != nil {
					ce.Write(
						zap.String("proto", resp.Proto),
						zap.String("status", resp.Status),
						zap.Strings("location", location),
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
				case fixedHost, "":
				default:
					resp.Close = true
				}
			}

			if ce := logger.Check(zap.DebugLevel, "Writing HTTP response"); ce != nil {
				ce.Write(
					zap.String("proto", resp.Proto),
					zap.String("status", resp.Status),
				)
			}

			// Write response.
			if rerr = resp.Write(rwbw); rerr != nil {
				rerr = fmt.Errorf("failed to write HTTP response: %w", rerr)
				break
			}

			// Flush response.
			if rerr = rwbw.Flush(); rerr != nil {
				rerr = fmt.Errorf("failed to flush HTTP response: %w", rerr)
				break
			}

			// Stop relaying if either client or server indicates that the connection should be closed.
			//
			// RFC 7230 section 6.6 says:
			// The server SHOULD send a "close" connection option in its final response on that connection.
			//
			// It's not a "MUST", so we check both.
			if req.Close || resp.Close {
				break
			}

			// Read request.
			req, werr = http.ReadRequest(rwbr)
			if werr != nil {
				if werr != io.EOF {
					werr = fmt.Errorf("failed to read HTTP request: %w", werr)
				}
				break
			}

			// Close the proxy connection if the destination host changes.
			// The client should seamlessly open a new connection.
			if req.Host != fixedHost {
				break
			}
		}

		pl.CloseReadWithError(rerr)
		pl.CloseWriteWithError(werr)
		rw.Close()
	}()

	// Wrap pr into a direct stream ReadWriter.
	return direct.NewDirectStreamReadWriter(pr), targetAddr, nil
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

func send400(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	return err
}

func send502(w io.Writer) error {
	_, err := w.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	return err
}

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
	"github.com/database64128/shadowsocks-go/magic"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

// NewHttpStreamServerReadWriter handles a HTTP request from rw and wraps rw into a ReadWriter ready for use.
func NewHttpStreamServerReadWriter(rw zerocopy.DirectReadWriteCloser, logger *zap.Logger) (*direct.DirectStreamReadWriter, conn.Addr, error) {
	rwbr := bufio.NewReader(rw)
	req, err := magic.ReadRequest(rwbr)
	if err != nil {
		return nil, conn.Addr{}, err
	}

	// Host -> targetAddr
	targetAddr, err := hostHeaderToAddr(req.Host)
	if err != nil {
		send418(rw)
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
		plbr := bufio.NewReader(pl)
		plbw := bufio.NewWriter(pl)
		rwbw := bufio.NewWriter(rw)

		for {
			// Delete hop-by-hop headers specified in Connection.
			var closeAfterResp bool
			connectionHeader := req.Header["Connection"]
			for _, v := range connectionHeader {
				if strings.EqualFold(v, "close") {
					closeAfterResp = true
				}
				req.Header.Del(v)
			}
			delete(req.Header, "Connection")

			delete(req.Header, "Proxy-Connection")

			// Write request.
			err := req.Write(plbw)
			if err != nil {
				logger.Warn("Failed to write HTTP request",
					zap.String("proto", req.Proto),
					zap.String("method", req.Method),
					zap.String("url", req.RequestURI),
					zap.Error(err),
				)
				break
			}

			// Flush request.
			err = plbw.Flush()
			if err != nil {
				logger.Warn("Failed to flush HTTP request",
					zap.String("proto", req.Proto),
					zap.String("method", req.Method),
					zap.String("url", req.RequestURI),
					zap.Error(err),
				)
				break
			}

			// Read response.
			resp, err := http.ReadResponse(plbr, req)
			if err != nil {
				logger.Warn("Failed to read HTTP response",
					zap.String("proto", req.Proto),
					zap.String("method", req.Method),
					zap.String("url", req.RequestURI),
					zap.Error(err),
				)
				break
			}

			// Add Connection: close if response is 301, 302, or 307,
			// and Location points to a different host.
			switch resp.StatusCode {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect:
				location := resp.Header["Location"]
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

			// Write response.
			err = resp.Write(rwbw)
			if err != nil {
				logger.Warn("Failed to write HTTP response",
					zap.String("proto", resp.Proto),
					zap.String("status", resp.Status),
					zap.String("proto", resp.Proto),
					zap.Error(err),
				)
				break
			}

			// Flush response.
			err = rwbw.Flush()
			if err != nil {
				logger.Warn("Failed to flush HTTP response",
					zap.String("proto", resp.Proto),
					zap.String("status", resp.Status),
					zap.String("proto", resp.Proto),
					zap.Error(err),
				)
				break
			}

			if closeAfterResp || req.ProtoMajor == 1 && req.ProtoMinor == 0 {
				break
			}

			// Read request.
			req, err = magic.ReadRequest(rwbr)
			if err != nil {
				if err != io.EOF {
					logger.Warn("Failed to read HTTP request", zap.Error(err))
				}
				break
			}
		}

		if err := pl.Close(); err != nil {
			logger.Warn("Failed to close pipe", zap.Error(err))
		}
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

func send418(w io.Writer) error {
	_, err := fmt.Fprint(w, "HTTP/1.1 418 I'm a teapot\r\n\r\n")
	return err
}

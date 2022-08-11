package http

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

var ErrServerSpokeFirst = errors.New("server-speaks-first protocols are not supported by this HTTP proxy client implementation")

// NewHttpStreamClientReadWriter writes a HTTP/1.1 CONNECT request to rw and wraps rw into a ReadWriter ready for use.
func NewHttpStreamClientReadWriter(rw zerocopy.DirectReadWriteCloser, targetAddr conn.Addr) (*direct.DirectStreamReadWriter, error) {
	targetAddress := targetAddr.String()

	// Write CONNECT.
	_, err := fmt.Fprintf(rw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: shadowsocks-go/0.0.0\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddress, targetAddress)
	if err != nil {
		return nil, err
	}

	// Read response.
	br := bufio.NewReader(rw)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	// Check if server spoke first.
	if br.Buffered() > 0 {
		return nil, ErrServerSpokeFirst
	}

	return direct.NewDirectStreamReadWriter(rw), nil
}

package probe

import (
	"bufio"
	"context"
	"fmt"
	"net/http"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
)

// TCPProbeConfig is the configuration for a TCP probe.
type TCPProbeConfig struct {
	// Addr is the address of the HTTP test endpoint.
	Addr conn.Addr

	// EscapedPath is the escaped URL path of the HTTP test endpoint.
	EscapedPath string

	// Host specifies the value of the Host header field in the HTTP request.
	Host string
}

// NewProbe creates a new TCP probe from the configuration.
func (c TCPProbeConfig) NewProbe() TCPProbe {
	return TCPProbe{
		addr: c.Addr,
		req:  fmt.Appendf(nil, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", c.EscapedPath, c.Host),
	}
}

// TCPProbe tests the connectivity of a TCP client by sending an HTTP GET request
// to the configured endpoint. The response status code must be 204 No Content.
type TCPProbe struct {
	addr conn.Addr
	req  []byte
}

// Probe runs the connectivity test.
func (p TCPProbe) Probe(ctx context.Context, client netio.StreamClient) error {
	c, err := client.DialStream(ctx, p.addr, p.req)
	if err != nil {
		return fmt.Errorf("failed to create remote connection: %w", err)
	}
	defer c.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = c.SetReadDeadline(conn.ALongTimeAgo)
	})
	defer stop()

	br := bufio.NewReader(c)

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
	}

	return nil
}

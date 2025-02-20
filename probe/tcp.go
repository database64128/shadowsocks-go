package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/zerocopy"
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
func (p TCPProbe) Probe(ctx context.Context, client zerocopy.TCPClient) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialer, _ := client.NewDialer()

	rawRW, rw, err := dialer.Dial(ctx, p.addr, p.req)
	if err != nil {
		return fmt.Errorf("failed to create remote connection: %w", err)
	}
	defer rw.Close()

	if tc, ok := rawRW.(*net.TCPConn); ok {
		go func() {
			<-ctx.Done()
			_ = tc.SetReadDeadline(conn.ALongTimeAgo)
		}()
	}

	cr := zerocopy.NewCopyReader(rw)
	br := bufio.NewReader(cr)

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

// ProbeRTT runs the connectivity test and returns the round-trip time.
func (p TCPProbe) ProbeRTT(ctx context.Context, client zerocopy.TCPClient) (rtt time.Duration, err error) {
	start := time.Now()
	err = p.Probe(ctx, client)
	return time.Since(start), err
}

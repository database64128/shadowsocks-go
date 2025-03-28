package netiotest

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/nettest"
)

// PipeStreamClient handles stream connection requests by creating a pipe
// for each DialStream call and sending the server end to a channel.
type PipeStreamClient struct {
	ch   chan<- *PipeConn
	info netio.StreamDialerInfo
}

// NewPipeStreamClient returns a new [*PipeStreamClient] and a channel for
// receiving server ends of the pipes.
func NewPipeStreamClient(info netio.StreamDialerInfo) (*PipeStreamClient, <-chan *PipeConn) {
	ch := make(chan *PipeConn, 1)
	return &PipeStreamClient{
		ch:   ch,
		info: info,
	}, ch
}

// Close closes the pipe channel.
func (c *PipeStreamClient) Close() error {
	close(c.ch)
	return nil
}

// NewStreamDialer implements [netio.StreamClient.NewStreamDialer].
func (c *PipeStreamClient) NewStreamDialer() (netio.StreamDialer, netio.StreamDialerInfo) {
	return c, c.info
}

// DialStream implements [netio.StreamDialer.DialStream].
func (c *PipeStreamClient) DialStream(ctx context.Context, addr conn.Addr, payload []byte) (plc netio.Conn, err error) {
	ctxDone := ctx.Done()
	pl, pr := netio.NewPipe()

	select {
	case <-ctxDone:
		return nil, ctx.Err()
	case c.ch <- &PipeConn{
		PipeConn:      pr,
		localConnAddr: addr,
	}:
	}

	if len(payload) > 0 {
		if _, err = netio.ConnWriteContext(ctx, pl, payload); err != nil {
			return nil, err
		}
	}

	return &PipeConn{
		PipeConn:       pl,
		remoteConnAddr: addr,
	}, nil
}

// PipeConn is [*netio.PipeConn] with additional local and remote addresses.
type PipeConn struct {
	*netio.PipeConn
	localConnAddr  conn.Addr
	remoteConnAddr conn.Addr
}

// LocalConnAddr returns the local address of the connection, if known.
func (c *PipeConn) LocalConnAddr() conn.Addr {
	return c.localConnAddr
}

// RemoteConnAddr returns the remote address of the connection, if known.
func (c *PipeConn) RemoteConnAddr() conn.Addr {
	return c.remoteConnAddr
}

var testAddrCases = [...]struct {
	name string
	addr conn.Addr
}{
	{
		name: "IPv4",
		addr: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 10004),
	},
	{
		name: "IPv6",
		addr: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 16666),
	},
	{
		name: "Domain",
		addr: conn.MustAddrFromDomainPort("example.com", 10080),
	},
}

var testInitialPayloadCases = [...]struct {
	name    string
	payload func() []byte
}{
	{
		name: "Empty",
		payload: func() []byte {
			return nil
		},
	},
	{
		name: "Short",
		payload: func() []byte {
			return []byte("Hello, world!")
		},
	},
	{
		name: "4k",
		payload: func() []byte {
			b := make([]byte, 4096)
			rand.Read(b)
			return b
		},
	},
	{
		name: "1M",
		payload: func() []byte {
			b := make([]byte, 1<<20)
			rand.Read(b)
			return b
		},
	},
}

// TestPreambleStreamClientServerProceed tests a pair of stream client and server
// implementations that, after performing whatever protocol-specific handshake,
// simply return the underlying connection to the caller.
func TestPreambleStreamClientServerProceed(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
	expectedServerAddr conn.Addr,
	expectedUsername string,
) {
	for _, addrCase := range testAddrCases {
		t.Run(addrCase.name, func(t *testing.T) {
			for _, payloadCase := range testInitialPayloadCases {
				t.Run(payloadCase.name, func(t *testing.T) {
					testPreambleStreamClientServerProceed(
						t,
						newClient,
						addrCase.addr,
						payloadCase.payload(),
						server,
						expectedServerAddr,
						expectedUsername,
					)
				})
			}
		})
	}
}

func testPreambleStreamClientServerProceed(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	addr conn.Addr,
	initialPayload []byte,
	server netio.StreamServer,
	expectedServerAddr conn.Addr,
	expectedUsername string,
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	expectedInitialPayload := slices.Clone(initialPayload)

	go func() {
		defer psc.Close()

		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			if !pc.LocalConnAddr().Equals(expectedServerAddr) {
				t.Errorf("pc.LocalConnAddr() = %v, want %v", pc.LocalConnAddr(), expectedServerAddr)
			}

			req, err := server.HandleStream(pc, logger)
			if err != nil {
				t.Errorf("server.HandleStream failed: %v", err)
				return
			}
			if !req.Addr.Equals(addr) {
				t.Errorf("req.Addr = %v, want %v", req.Addr, addr)
			}
			if len(req.Payload) > len(expectedInitialPayload) {
				t.Errorf("req.Payload = %v, want %v", req.Payload, expectedInitialPayload)
			}
			if req.Username != expectedUsername {
				t.Errorf("req.Username = %q, want %q", req.Username, expectedUsername)
			}

			serverConn, err := req.Proceed()
			if err != nil {
				t.Errorf("req.Proceed failed: %v", err)
				return
			}
			defer serverConn.Close()

			if _, ok := serverConn.(*PipeConn); !ok {
				t.Errorf("serverConn is %T, want *PipeConn", serverConn)
			}

			_ = serverConn.CloseWrite()

			buf := bytes.NewBuffer(req.Payload)
			if _, err = io.Copy(buf, serverConn); err != nil {
				t.Errorf("io.Copy failed: %v", err)
			}
			if got := buf.Bytes(); !bytes.Equal(got, expectedInitialPayload) {
				t.Errorf("buf.Bytes() = %v, want %v", got, expectedInitialPayload)
			}
		}
	}()

	client := newClient(psc)

	clientConn, err := client.DialStream(ctx, addr, initialPayload)
	if err != nil {
		t.Fatalf("DialStream failed: %v", err)
	}
	defer clientConn.Close()

	if _, ok := clientConn.(*PipeConn); !ok {
		t.Errorf("clientConn is %T, want *PipeConn", clientConn)
	}

	_ = clientConn.CloseWrite()

	if _, err := clientConn.Read(nil); err != io.EOF {
		t.Errorf("clientConn.Read() = %v, want io.EOF", err)
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than once")
	}
}

// TestWrapConnStreamClientServerProceed tests a pair of stream client and server
// implementations that return wrapper connections over the underlying connection.
func TestWrapConnStreamClientServerProceed(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
	expectedServerAddr conn.Addr,
	expectedUsername string,
) {
	for _, addrCase := range testAddrCases {
		t.Run(addrCase.name, func(t *testing.T) {
			for _, payloadCase := range testInitialPayloadCases {
				t.Run(payloadCase.name, func(t *testing.T) {
					testWrapConnStreamClientServerProceed(
						t,
						newClient,
						addrCase.addr,
						payloadCase.payload(),
						server,
						expectedServerAddr,
						expectedUsername,
					)
				})
			}
		})
	}
}

func testWrapConnStreamClientServerProceed(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	addr conn.Addr,
	initialPayload []byte,
	server netio.StreamServer,
	expectedServerAddr conn.Addr,
	expectedUsername string,
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	expectedInitialPayload := slices.Clone(initialPayload)

	type serverConnOrErr struct {
		serverConn netio.Conn
		err        error
	}

	serverConnOrErrCh := make(chan serverConnOrErr)

	go func() {
		for {
			select {
			case <-ctx.Done():
				t.Error("DialStream not called")
				return

			case pc, ok := <-ch:
				if !ok {
					return
				}

				if !pc.LocalConnAddr().Equals(expectedServerAddr) {
					t.Errorf("pc.LocalConnAddr() = %v, want %v", pc.LocalConnAddr(), expectedServerAddr)
				}

				req, err := server.HandleStream(pc, logger)
				if err != nil {
					t.Errorf("server.HandleStream failed: %v", err)
					serverConnOrErrCh <- serverConnOrErr{err: err}
					return
				}
				if !req.Addr.Equals(addr) {
					t.Errorf("req.Addr = %v, want %v", req.Addr, addr)
				}
				if len(req.Payload) > len(expectedInitialPayload) {
					t.Errorf("req.Payload = %v, want %v", req.Payload, expectedInitialPayload)
				}
				if req.Username != expectedUsername {
					t.Errorf("req.Username = %q, want %q", req.Username, expectedUsername)
				}

				serverConn, err := req.Proceed()
				if err != nil {
					t.Errorf("req.Proceed failed: %v", err)
					serverConnOrErrCh <- serverConnOrErr{err: err}
					return
				}

				b := slices.Grow(req.Payload, len(expectedInitialPayload)-len(req.Payload))[:len(expectedInitialPayload)]
				readBuf := b[len(req.Payload):]
				if _, err = io.ReadFull(serverConn, readBuf); err != nil {
					t.Errorf("io.ReadFull failed: %v", err)
				}
				if !bytes.Equal(b, expectedInitialPayload) {
					t.Errorf("b = %v, want %v", b, expectedInitialPayload)
				}

				serverConnOrErrCh <- serverConnOrErr{serverConn: serverConn}
			}
		}
	}()

	client := newClient(psc)

	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		clientConn, err := client.DialStream(ctx, addr, initialPayload)
		if err != nil {
			return nil, nil, nil, err
		}

		serverConnOrErr := <-serverConnOrErrCh
		if serverConnOrErr.err != nil {
			return nil, nil, nil, serverConnOrErr.err
		}
		serverConn := serverConnOrErr.serverConn

		// Hide the connections behind pipes to satisfy synchronization requirements.
		c1, c1pr := netio.NewPipe()
		go func() {
			_, _, _ = netio.BidirectionalCopy(clientConn, pipeConnWithoutWriteTo{PipeConn: c1pr})
		}()

		c2, c2pr := netio.NewPipe()
		go func() {
			_, _, _ = netio.BidirectionalCopy(serverConn, pipeConnWithoutWriteTo{PipeConn: c2pr})
		}()

		stop = func() {
			_ = c1.Close()
			_ = c2.Close()
		}
		return
	})

	_ = psc.Close()

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than expected")
	}
}

// pipeConnWithoutWriteTo wraps a [*netio.PipeConn] to hide its WriteTo method.
// This is useful for testing with [nettest.TestConn], as a blocked writer can
// cause the test to hang.
type pipeConnWithoutWriteTo struct {
	noWriteTo
	*netio.PipeConn
}

// noWriteTo can be embedded alongside another type to
// hide the WriteTo method of that other type.
type noWriteTo struct{}

// WriteTo hides another WriteTo method.
// It should never be called.
func (noWriteTo) WriteTo(io.Writer) (int64, error) {
	panic("can't happen")
}

// TestStreamClientServerAbort tests a pair of stream client and server
// implementations for handling aborted connection requests.
func TestStreamClientServerAbort(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
	checkDialErr func(t *testing.T, dialResult conn.DialResult, err error),
) {
	for _, dialResultCase := range [...]struct {
		name       string
		dialResult conn.DialResult
	}{
		{
			name: "Success",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeSuccess,
			},
		},
		{
			name: "EACCES",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeEACCES,
			},
		},
		{
			name: "ENETDOWN",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeENETDOWN,
			},
		},
		{
			name: "ENETUNREACH",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeENETUNREACH,
			},
		},
		{
			name: "ENETRESET",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeENETRESET,
			},
		},
		{
			name: "ECONNABORTED",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeECONNABORTED,
			},
		},
		{
			name: "ECONNRESET",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeECONNRESET,
			},
		},
		{
			name: "ETIMEDOUT",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeETIMEDOUT,
			},
		},
		{
			name: "ECONNREFUSED",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeECONNREFUSED,
			},
		},
		{
			name: "EHOSTDOWN",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeEHOSTDOWN,
			},
		},
		{
			name: "EHOSTUNREACH",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeEHOSTUNREACH,
			},
		},
		{
			name: "ErrDomainNameLookup",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeErrDomainNameLookup,
				Err:  &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
			},
		},
		{
			name: "ErrOther",
			dialResult: conn.DialResult{
				Code: conn.DialResultCodeErrOther,
				Err:  &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
			},
		},
	} {
		t.Run(dialResultCase.name, func(t *testing.T) {
			for _, addrCase := range testAddrCases {
				t.Run(addrCase.name, func(t *testing.T) {
					for _, payloadCase := range testInitialPayloadCases {
						t.Run(payloadCase.name, func(t *testing.T) {
							testStreamClientServerAbort(
								t,
								newClient,
								addrCase.addr,
								payloadCase.payload(),
								server,
								dialResultCase.dialResult,
								checkDialErr,
							)
						})
					}
				})
			}
		})
	}
}

func testStreamClientServerAbort(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	addr conn.Addr,
	initialPayload []byte,
	server netio.StreamServer,
	dialResult conn.DialResult,
	checkDialErr func(t *testing.T, dialResult conn.DialResult, err error),
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	go func() {
		defer psc.Close()

		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			defer pc.Close()

			req, err := server.HandleStream(pc, logger)
			if err != nil {
				t.Errorf("server.HandleStream failed: %v", err)
				return
			}

			if err = req.Abort(dialResult); err != nil {
				t.Errorf("req.Abort failed: %v", err)
			}
		}
	}()

	client := newClient(psc)

	_, err := client.DialStream(ctx, addr, initialPayload)
	checkDialErr(t, dialResult, err)

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than once")
	}
}

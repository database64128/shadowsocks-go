package netiotest

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

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

// aLongTimeAgo is a non-zero time, far in the past, used for immediate deadlines.
var aLongTimeAgo = time.Unix(0, 0)

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

	if ctxDone != nil {
		done := make(chan struct{})
		interruptRes := make(chan error)

		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil && err == nil {
				err = ctxErr
			}
		}()

		go func() {
			select {
			case <-ctxDone:
				pl.SetWriteDeadline(aLongTimeAgo)
				interruptRes <- ctx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	if _, err := pl.Write(payload); err != nil {
		return nil, err
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
		addr: conn.AddrFromIPPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 10004)),
	},
	{
		name: "IPv6",
		addr: conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 16666)),
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
	dialer, _ := client.NewStreamDialer()

	clientConn, err := dialer.DialStream(ctx, addr, initialPayload)
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

// RWSerializedConn serializes Read and Write calls on a [netio.Conn].
type RWSerializedConn struct {
	netio.Conn
	rdMu sync.Mutex
	wrMu sync.Mutex
}

// NewRWSerializedConn returns a new [*RWSerializedConn] wrapping the given [netio.Conn].
func NewRWSerializedConn(c netio.Conn) *RWSerializedConn {
	return &RWSerializedConn{Conn: c}
}

// Read implements [netio.Conn.Read].
func (c *RWSerializedConn) Read(b []byte) (n int, err error) {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	return c.Conn.Read(b)
}

// Write implements [netio.Conn.Write].
func (c *RWSerializedConn) Write(b []byte) (n int, err error) {
	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	return c.Conn.Write(b)
}

// TestWrapConnStreamClientServerProceed tests a pair of stream client and server
// implementations that return wrapper connections over the underlying connection.
func TestWrapConnStreamClientServerProceed(
	t *testing.T,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
	expectedServerAddr conn.Addr,
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
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	var serverConn netio.Conn
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

			serverConn, err = req.Proceed()
			if err != nil {
				t.Errorf("req.Proceed failed: %v", err)
				return
			}
			defer serverConn.Close()

			b := slices.Grow(req.Payload, len(expectedInitialPayload)-len(req.Payload))[:len(expectedInitialPayload)]
			readBuf := b[len(req.Payload):]
			if _, err = io.ReadFull(serverConn, readBuf); err != nil {
				t.Errorf("io.ReadFull failed: %v", err)
			}
			if !bytes.Equal(b, expectedInitialPayload) {
				t.Errorf("b = %v, want %v", b, expectedInitialPayload)
			}
		}
	}()

	client := newClient(psc)
	dialer, _ := client.NewStreamDialer()

	clientConn, err := dialer.DialStream(ctx, addr, initialPayload)
	if err != nil {
		t.Fatalf("DialStream failed: %v", err)
	}
	defer clientConn.Close()

	if _, ok := clientConn.(*PipeConn); !ok {
		t.Errorf("clientConn is %T, want *PipeConn", clientConn)
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than once")
	}

	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		c1 = NewRWSerializedConn(clientConn)
		c2 = NewRWSerializedConn(serverConn)
		stop = func() {
			_ = c1.Close()
			_ = c2.Close()
		}
		return
	})
}

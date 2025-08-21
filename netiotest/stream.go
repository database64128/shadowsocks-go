package netiotest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"go.uber.org/zap/zaptest"
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
			t.Parallel()
			for _, payloadCase := range testInitialPayloadCases {
				t.Run(payloadCase.name, func(t *testing.T) {
					t.Parallel()
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
			t.Parallel()
			for _, payloadCase := range testInitialPayloadCases {
				t.Run(payloadCase.name, func(t *testing.T) {
					t.Parallel()
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
		for pc := range ch {
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
	}()

	client := newClient(psc)

	t.Run("RoundTrip", func(t *testing.T) {
		TestConnPairRoundTrip(t, func() (c1, c2 netio.Conn) {
			clientConn, err := client.DialStream(ctx, addr, initialPayload)
			if err != nil {
				t.Fatalf("DialStream failed: %v", err)
			}

			serverConnOrErr := <-serverConnOrErrCh
			if serverConnOrErr.err != nil {
				t.FailNow()
			}

			return clientConn, serverConnOrErr.serverConn
		})
	})

	_ = psc.Close()

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than expected")
	}
}

// TestConnPairRoundTrip tests a pair of connections for round-trip communication.
func TestConnPairRoundTrip(t *testing.T, newConnPair func() (c1, c2 netio.Conn)) {
	for _, sizeCase := range [...]struct {
		name     string
		copySize int
	}{
		{"0", 0},
		{"1", 1},
		{"4k", 4096},
		{"1M", 1 << 20},
	} {
		t.Run(sizeCase.name, func(t *testing.T) {
			t.Parallel()
			c1, c2 := newConnPair()
			testConnPairRoundTrip(t, sizeCase.copySize, c1, c2)

			_, c1wt := c1.(io.WriterTo)
			_, c2wt := c2.(io.WriterTo)
			_, c1rf := c1.(io.ReaderFrom)
			_, c2rf := c2.(io.ReaderFrom)

			if c1wt || c2wt {
				t.Run("HideWriteTo", func(t *testing.T) {
					t.Parallel()
					c1, c2 := newConnPair()
					testConnPairRoundTrip(t, sizeCase.copySize, hideConnWriteTo(c1), hideConnWriteTo(c2))
				})
			}

			if c1rf || c2rf {
				t.Run("HideWriteToReadFrom", func(t *testing.T) {
					t.Parallel()
					c1, c2 := newConnPair()
					testConnPairRoundTrip(t, sizeCase.copySize, hideConnWriteToReadFrom(c1), hideConnWriteToReadFrom(c2))
				})
			}

			if c1wt || c2wt || c1rf || c2rf {
				t.Run("BidirectionalCopy", func(t *testing.T) {
					t.Parallel()
					c1, c3 := newConnPair()
					c4, c2 := newConnPair()
					testConnPairRoundTripBidirectionalCopy(t, sizeCase.copySize, c1, c2, c3, c4, netio.BidirectionalCopy)
				})

				t.Run("BidirectionalCopyNoWriteTo", func(t *testing.T) {
					t.Parallel()
					c1, c3 := newConnPair()
					c4, c2 := newConnPair()
					testConnPairRoundTripBidirectionalCopy(t, sizeCase.copySize, c1, c2, c3, c4, bidirectionalCopyNoWriteTo)
				})
			}

			if c1wt && c2wt && c1rf && c2rf {
				t.Run("InterleaveReadWriteToWriteReadFrom", func(t *testing.T) {
					t.Parallel()
					c1, c2 := newConnPair()
					testConnPairRoundTripInterleaveReadWriteToWriteReadFrom(t, sizeCase.copySize, c1, c2)
				})
			}
		})
	}
}

func testConnPairRoundTrip(t *testing.T, copySize int, c1, c2 netio.Conn) {
	const copyCount = 10
	bufSize := copySize * copyCount
	want := make([]byte, bufSize)
	rand.Read(want)

	var makeCopyBuf func() []byte
	if copySize > 0 {
		makeCopyBuf = func() []byte {
			return make([]byte, copySize)
		}
	} else {
		makeCopyBuf = func() []byte {
			return nil
		}
	}

	var wg sync.WaitGroup

	readFunc := func(name string, c netio.Conn) {
		var buf bytes.Buffer
		buf.Grow(bufSize)
		w := hideWriterReadFrom(&buf)
		if _, err := io.CopyBuffer(w, c, makeCopyBuf()); err != nil {
			t.Errorf("Copy w <- %s failed: %v", name, err)
		}
		if got := buf.Bytes(); !bytes.Equal(got, want) {
			t.Error("got != want")
		}
	}
	wg.Go(func() { readFunc("c1", c1) })
	wg.Go(func() { readFunc("c2", c2) })

	writeFunc := func(name string, c netio.Conn) {
		r := hideReaderWriteTo(bytes.NewReader(want))
		if _, err := io.CopyBuffer(c, r, makeCopyBuf()); err != nil {
			t.Errorf("Copy %s <- r failed: %v", name, err)
		}
		_ = c.CloseWrite()
	}
	wg.Go(func() { writeFunc("c1", c1) })
	wg.Go(func() { writeFunc("c2", c2) })

	wg.Wait()

	_ = c1.Close()
	_ = c2.Close()
}

func testConnPairRoundTripBidirectionalCopy(
	t *testing.T,
	copySize int,
	c1, c2, c3, c4 netio.Conn,
	bidirectionalCopy func(left, right netio.ReadWriter) (nl2r, nr2l int64, err error),
) {
	var wg sync.WaitGroup
	wg.Go(func() {
		if _, _, err := bidirectionalCopy(c3, c4); err != nil {
			t.Errorf("Bidirectional copy c3 <-> c4 failed: %v", err)
		}
		_ = c3.Close()
		_ = c4.Close()
	})
	testConnPairRoundTrip(t, copySize, c1, c2)
	wg.Wait()
}

func testConnPairRoundTripInterleaveReadWriteToWriteReadFrom(t *testing.T, copySize int, c1, c2 netio.Conn) {
	const copyCount = 10
	bufSize := copySize * copyCount
	want := make([]byte, bufSize)
	rand.Read(want)

	var wg sync.WaitGroup

	// Read the first half, then WriteTo the second half.
	readFunc := func(name string, c netio.Conn) {
		got1 := make([]byte, bufSize/2)
		if _, err := io.ReadFull(c, got1); err != nil {
			t.Errorf("Read %s -> got1 failed: %v", name, err)
		}
		if !bytes.Equal(got1, want[:len(got1)]) {
			t.Error("got1 != want1")
		}

		var buf bytes.Buffer
		buf.Grow(bufSize / 2)
		if _, err := c.(io.WriterTo).WriteTo(&buf); err != nil {
			t.Errorf("WriteTo %s -> buf failed: %v", name, err)
		}
		if got2 := buf.Bytes(); !bytes.Equal(got2, want[len(got1):]) {
			t.Error("got2 != want2")
		}
	}
	wg.Go(func() { readFunc("c1", c1) })
	wg.Go(func() { readFunc("c2", c2) })

	// Interleave Write and ReadFrom, each writing copySize bytes.
	writeFunc := func(name string, c netio.Conn) {
		var r bytes.Reader
		b := want
		for range 5 {
			if _, err := c.Write(b[:copySize]); err != nil {
				t.Errorf("Write %s <- b failed: %v", name, err)
			}
			b = b[copySize:]

			r.Reset(b[:copySize])
			b = b[copySize:]
			if _, err := c.(io.ReaderFrom).ReadFrom(&r); err != nil {
				t.Errorf("ReadFrom %s <- r failed: %v", name, err)
			}
		}
		_ = c.CloseWrite()
	}
	wg.Go(func() { writeFunc("c1", c1) })
	wg.Go(func() { writeFunc("c2", c2) })

	wg.Wait()

	_ = c1.Close()
	_ = c2.Close()
}

func bidirectionalCopyNoWriteTo(left, right netio.ReadWriter) (nl2r, nr2l int64, err error) {
	var (
		wg     sync.WaitGroup
		l2rErr error
	)

	wg.Go(func() {
		nl2r, l2rErr = copyNoWriteTo(right, left)
		_ = right.CloseWrite()
	})

	nr2l, err = copyNoWriteTo(left, right)
	_ = left.CloseWrite()
	wg.Wait()

	return nl2r, nr2l, errors.Join(l2rErr, err)
}

func copyNoWriteTo(dst io.Writer, src io.Reader) (int64, error) {
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(dst, hideReaderWriteTo(src))
}

func hideReaderWriteTo(r io.Reader) io.Reader {
	return struct{ io.Reader }{r}
}

func hideWriterReadFrom(w io.Writer) io.Writer {
	return struct{ io.Writer }{w}
}

func hideConnWriteTo(c netio.Conn) netio.Conn {
	if rf, ok := c.(io.ReaderFrom); ok {
		return struct {
			io.ReaderFrom
			netio.Conn
		}{rf, c}
	}
	return hideConnWriteToReadFrom(c)
}

func hideConnWriteToReadFrom(c netio.Conn) netio.Conn {
	return struct{ netio.Conn }{c}
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
			t.Parallel()
			for _, addrCase := range testAddrCases {
				t.Run(addrCase.name, func(t *testing.T) {
					t.Parallel()
					for _, payloadCase := range testInitialPayloadCases {
						t.Run(payloadCase.name, func(t *testing.T) {
							t.Parallel()
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

// BenchmarkStreamClientServer tests the performance of the stream client and server connections.
func BenchmarkStreamClientServer(
	b *testing.B,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
	writeSize int,
) {
	ctx := b.Context()
	logger := zaptest.NewLogger(b)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	go func() {
		defer psc.Close()

		select {
		case <-ctx.Done():
			b.Error("DialStream not called")
			return

		case pc := <-ch:
			req, err := server.HandleStream(pc, logger)
			if err != nil {
				b.Errorf("server.HandleStream failed: %v", err)
				return
			}

			serverConn, err := req.Proceed()
			if err != nil {
				b.Errorf("req.Proceed failed: %v", err)
				return
			}
			defer serverConn.Close()

			if _, err := io.Copy(io.Discard, serverConn); err != nil {
				b.Errorf("io.Copy(io.Discard, serverConn) failed: %v", err)
			}

			if rf, ok := serverConn.(io.ReaderFrom); ok {
				b.Run("ServerReadFrom", func(b *testing.B) {
					var n int64
					for b.Loop() {
						nn, err := rf.ReadFrom(benchReader{})
						if err != nil {
							b.Fatalf("serverConn.ReadFrom failed: %v", err)
						}
						n += nn
					}
					b.SetBytes(n / int64(b.N))
				})
			}

			b.Run("ServerWrite", func(b *testing.B) {
				var n int64
				writeBuf := make([]byte, writeSize)
				for b.Loop() {
					nn, err := serverConn.Write(writeBuf)
					if err != nil {
						b.Fatalf("serverConn.Write failed: %v", err)
					}
					n += int64(nn)
				}
				b.SetBytes(n / int64(b.N))
			})

			_ = serverConn.CloseWrite()
		}
	}()

	client := newClient(psc)
	addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 5201)
	clientConn, err := client.DialStream(ctx, addr, nil)
	if err != nil {
		b.Fatalf("DialStream failed: %v", err)
	}
	defer clientConn.Close()

	if rf, ok := clientConn.(io.ReaderFrom); ok {
		b.Run("ClientReadFrom", func(b *testing.B) {
			var n int64
			for b.Loop() {
				nn, err := rf.ReadFrom(benchReader{})
				if err != nil {
					b.Fatalf("clientConn.ReadFrom failed: %v", err)
				}
				n += nn
			}
			b.SetBytes(n / int64(b.N))
		})
	}

	b.Run("ClientWrite", func(b *testing.B) {
		var n int64
		writeBuf := make([]byte, writeSize)
		for b.Loop() {
			nn, err := clientConn.Write(writeBuf)
			if err != nil {
				b.Fatalf("clientConn.Write failed: %v", err)
			}
			n += int64(nn)
		}
		b.SetBytes(n / int64(b.N))
	})

	_ = clientConn.CloseWrite()

	if _, err := io.Copy(io.Discard, clientConn); err != nil {
		b.Errorf("io.Copy(io.Discard, clientConn) failed: %v", err)
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		b.Error("DialStream called more than once")
	}
}

type benchReader struct{}

func (benchReader) Read(p []byte) (n int, err error) {
	return len(p), io.EOF
}

// BenchmarkStreamClientDialServerHandle tests the performance of the
// stream client and server establishing and closing connections.
func BenchmarkStreamClientDialServerHandle(
	b *testing.B,
	newClient func(psc *PipeStreamClient) netio.StreamClient,
	server netio.StreamServer,
) {
	ctx := b.Context()
	logger := zaptest.NewLogger(b)
	defer logger.Sync()

	psc, ch := NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	serverDrainBuf := make([]byte, 1)

	go func() {
		var wg sync.WaitGroup
		for pc := range ch {
			wg.Go(func() {
				req, err := server.HandleStream(pc, logger)
				if err != nil {
					b.Errorf("server.HandleStream failed: %v", err)
					return
				}

				serverConn, err := req.Proceed()
				if err != nil {
					b.Errorf("req.Proceed failed: %v", err)
					return
				}

				n, err := serverConn.Read(serverDrainBuf)
				if n != 0 || err != io.EOF {
					b.Errorf("serverConn.Read() = %d, %v, want 0, io.EOF", n, err)
				}

				_ = serverConn.Close()
			})
		}
		wg.Wait()
	}()

	client := newClient(psc)
	addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 5201)
	clientDrainBuf := make([]byte, 1)

	for _, parallelism := range [...]int{1, 2, 4, 8, 12} {
		b.Run(strconv.Itoa(parallelism), func(b *testing.B) {
			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					clientConn, err := client.DialStream(ctx, addr, nil)
					if err != nil {
						b.Errorf("DialStream failed: %v", err)
						continue
					}

					_ = clientConn.CloseWrite()

					n, err := clientConn.Read(clientDrainBuf)
					if n != 0 || err != io.EOF {
						b.Errorf("clientConn.Read() = %d, %v, want 0, io.EOF", n, err)
					}

					_ = clientConn.Close()
				}
			})
		})
	}

	_ = psc.Close()

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		b.Error("DialStream called more than once")
	}
}

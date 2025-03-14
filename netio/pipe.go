package netio

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// onceError keeps the first stored error.
type onceError struct {
	err atomic.Pointer[error]
}

func newOnceError() *onceError {
	return &onceError{}
}

func (a *onceError) Store(err error) {
	_ = a.err.CompareAndSwap(nil, &err)
}

func (a *onceError) Load() error {
	return *a.err.Load()
}

// pipeDeadline is an abstraction for handling timeouts.
type pipeDeadline struct {
	mu     sync.Mutex // Guards timer and cancel
	timer  *time.Timer
	cancel chan struct{} // Must be non-nil
}

func makePipeDeadline() pipeDeadline {
	return pipeDeadline{cancel: make(chan struct{})}
}

// set sets the point in time when the deadline will time out.
// A timeout event is signaled by closing the channel returned by waiter.
// Once a timeout has occurred, the deadline can be refreshed by specifying a
// t value in the future.
//
// A zero value for t prevents timeout.
func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // Wait for the timer callback to finish and close cancel
	}
	d.timer = nil

	// Time is zero, then there is no deadline.
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	// Time in the future, setup a timer to cancel in the future.
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})
		return
	}

	// Time in the past, so close immediately.
	if !closed {
		close(d.cancel)
	}
}

// wait returns a channel that is closed when the deadline is exceeded.
func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// PipeConn is one end of a pipe.
// See [NewPipe] for more information.
//
// PipeConn implements [Conn].
type PipeConn struct {
	wrMu sync.Mutex // Serialize Write operations

	// Used by local Read to interact with remote Write.
	// Successful receive on rdRx is always followed by send on rdTx.
	rdRx <-chan []byte
	rdTx chan<- int

	// Used by local Write to interact with remote Read.
	// Successful send on wrTx is always followed by receive on wrRx.
	wrTx chan<- []byte
	wrRx <-chan int

	localDone  chan struct{}
	remoteDone <-chan struct{}

	closeLocalDone  func()
	closeRemoteDone func()

	readError  *onceError
	writeError *onceError

	readDeadline  pipeDeadline
	writeDeadline pipeDeadline
}

var _ Conn = (*PipeConn)(nil)

// NewPipe creates a synchronous, in-memory, full duplex
// network connection; both ends implement the [Conn] interface.
// Reads on one end are matched with writes on the other,
// copying data directly between the two; there is no internal
// buffering.
func NewPipe() (pl, pr *PipeConn) {
	cb1 := make(chan []byte)
	cb2 := make(chan []byte)
	cn1 := make(chan int)
	cn2 := make(chan int)
	done1 := make(chan struct{})
	done2 := make(chan struct{})
	closeDone1 := sync.OnceFunc(func() { close(done1) })
	closeDone2 := sync.OnceFunc(func() { close(done2) })
	oe1 := newOnceError()
	oe2 := newOnceError()

	return &PipeConn{
			rdRx: cb1, rdTx: cn1,
			wrTx: cb2, wrRx: cn2,
			localDone: done1, remoteDone: done2,
			closeLocalDone: closeDone1, closeRemoteDone: closeDone2,
			readError:     oe1,
			writeError:    oe2,
			readDeadline:  makePipeDeadline(),
			writeDeadline: makePipeDeadline(),
		}, &PipeConn{
			rdRx: cb2, rdTx: cn2,
			wrTx: cb1, wrRx: cn1,
			localDone: done2, remoteDone: done1,
			closeLocalDone: closeDone2, closeRemoteDone: closeDone1,
			readError:     oe2,
			writeError:    oe1,
			readDeadline:  makePipeDeadline(),
			writeDeadline: makePipeDeadline(),
		}
}

// LocalAddr implements [Conn.LocalAddr].
func (*PipeConn) LocalAddr() net.Addr { return pipeAddr{} }

// RemoteAddr implements [Conn.RemoteAddr].
func (*PipeConn) RemoteAddr() net.Addr { return pipeAddr{} }

// Read implements [Conn.Read].
func (p *PipeConn) Read(b []byte) (int, error) {
	n, err := p.read(b)
	if err != nil && err != io.EOF && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "read", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *PipeConn) read(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.localDone):
		return 0, p.readError.Load()
	case isClosedChan(p.readDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	select {
	case bw := <-p.rdRx:
		nr := copy(b, bw)
		p.rdTx <- nr
		return nr, nil
	case <-p.localDone:
		return 0, p.readError.Load()
	case <-p.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

// WriteTo implements [io.WriterTo].
func (p *PipeConn) WriteTo(w io.Writer) (int64, error) {
	n, err := p.writeTo(w)
	if err != nil && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "writeto", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *PipeConn) writeTo(w io.Writer) (n int64, err error) {
	for {
		switch {
		case isClosedChan(p.localDone):
			return n, p.writeToReadCloseError()
		case isClosedChan(p.readDeadline.wait()):
			return n, os.ErrDeadlineExceeded
		}

		select {
		case bw := <-p.rdRx:
			nw, err := w.Write(bw)
			n += int64(nw)
			p.rdTx <- nw
			if err != nil {
				return n, err
			}
		case <-p.localDone:
			return n, p.writeToReadCloseError()
		case <-p.readDeadline.wait():
			return n, os.ErrDeadlineExceeded
		}
	}
}

func (p *PipeConn) writeToReadCloseError() error {
	if rerr := p.readError.Load(); rerr != io.EOF {
		return rerr
	}
	return nil
}

// Write implements [Conn.Write].
func (p *PipeConn) Write(b []byte) (int, error) {
	n, err := p.write(b)
	if err != nil && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "write", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *PipeConn) write(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.remoteDone):
		return 0, p.writeCloseError()
	case isClosedChan(p.writeDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	p.wrMu.Lock() // Ensure entirety of b is written together
	defer p.wrMu.Unlock()
	for once := true; once || len(b) > 0; once = false {
		select {
		case p.wrTx <- b:
			nw := <-p.wrRx
			b = b[nw:]
			n += nw
		case <-p.remoteDone:
			return n, p.writeCloseError()
		case <-p.writeDeadline.wait():
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, nil
}

func (p *PipeConn) writeCloseError() error {
	if werr := p.writeError.Load(); werr != io.EOF {
		return werr
	}
	return io.ErrClosedPipe
}

// SetDeadline implements [Conn.SetDeadline].
func (p *PipeConn) SetDeadline(t time.Time) error {
	rerr := p.SetReadDeadline(t)
	werr := p.SetWriteDeadline(t)
	if rerr != nil {
		return rerr
	}
	return werr
}

// SetReadDeadline implements [Conn.SetReadDeadline].
func (p *PipeConn) SetReadDeadline(t time.Time) error {
	if isClosedChan(p.localDone) && p.readError.Load() == io.ErrClosedPipe {
		return io.ErrClosedPipe
	}
	p.readDeadline.set(t)
	return nil
}

// SetWriteDeadline implements [Conn.SetWriteDeadline].
func (p *PipeConn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(p.remoteDone) && p.writeError.Load() == io.EOF {
		return io.ErrClosedPipe
	}
	p.writeDeadline.set(t)
	return nil
}

// CloseReadWithError shuts down data transfer from the remote end to the local end.
// Subsequent reads on the local end and writes on the remote end will return the given error,
// or [io.ErrClosedPipe] if the error is nil.
func (p *PipeConn) CloseReadWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	p.readError.Store(err)
	p.closeLocalDone()
}

// CloseWriteWithError shuts down data transfer from the local end to the remote end.
// Subsequent writes on the local end and reads on the remote end will return the given error,
// or [io.ErrClosedPipe] and [io.EOF] respectively if the error is nil.
func (p *PipeConn) CloseWriteWithError(err error) {
	if err == nil {
		err = io.EOF
	}
	p.writeError.Store(err)
	p.closeRemoteDone()
}

// CloseWithError closes both ends of the pipe with the given error.
func (p *PipeConn) CloseWithError(err error) {
	p.CloseReadWithError(err)
	p.CloseWriteWithError(err)
}

// CloseRead shuts down data transfer from the remote end to the local end.
// Subsequent reads on the local end and writes on the remote end will return [io.ErrClosedPipe].
func (p *PipeConn) CloseRead() error {
	p.CloseReadWithError(nil)
	return nil
}

// CloseWrite shuts down data transfer from the local end to the remote end.
// Subsequent writes on the local end will return [io.ErrClosedPipe].
// Subsequent reads on the remote end will return [io.EOF].
//
// CloseWrite implements [Conn.CloseWrite].
func (p *PipeConn) CloseWrite() error {
	p.CloseWriteWithError(nil)
	return nil
}

// Close closes both ends of the pipe.
//
// Close implements [Conn.Close].
func (p *PipeConn) Close() error {
	p.CloseWithError(nil)
	return nil
}

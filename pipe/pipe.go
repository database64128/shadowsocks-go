package pipe

import "io"

// DuplexPipeEnd is one end of a duplex pipe.
type DuplexPipeEnd struct {
	r *io.PipeReader
	w *io.PipeWriter
}

// NewDuplexPipe assembles 2 pipes together as a duplex pipe
// and returns both ends of the duplex pipe.
func NewDuplexPipe() (*DuplexPipeEnd, *DuplexPipeEnd) {
	lr, lw := io.Pipe()
	rr, rw := io.Pipe()
	return &DuplexPipeEnd{
			r: lr,
			w: rw,
		}, &DuplexPipeEnd{
			r: rr,
			w: lw,
		}
}

// Read implements [io.Reader.Read].
func (p *DuplexPipeEnd) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

// Write implements [io.Writer.Write].
func (p *DuplexPipeEnd) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

// CloseRead closes the read pipe.
func (p *DuplexPipeEnd) CloseRead() error {
	return p.r.Close()
}

// CloseWrite closes the write pipe.
func (p *DuplexPipeEnd) CloseWrite() error {
	return p.w.Close()
}

// Close closes both read and write pipes.
func (p *DuplexPipeEnd) Close() error {
	_ = p.r.Close() // always returns nil
	_ = p.w.Close() // always returns nil
	return nil
}

// CloseReadWithError closes the read pipe with an error.
func (p *DuplexPipeEnd) CloseReadWithError(err error) {
	_ = p.r.CloseWithError(err) // always returns nil
}

// CloseWriteWithError closes the write pipe with an error.
func (p *DuplexPipeEnd) CloseWriteWithError(err error) {
	_ = p.w.CloseWithError(err) // always returns nil
}

// CloseWithError closes both read and write pipes with an error.
func (p *DuplexPipeEnd) CloseWithError(err error) {
	_ = p.r.CloseWithError(err) // always returns nil
	_ = p.w.CloseWithError(err) // always returns nil
}

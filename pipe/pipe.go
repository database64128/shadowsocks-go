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

func (p *DuplexPipeEnd) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *DuplexPipeEnd) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *DuplexPipeEnd) CloseRead() error {
	return p.r.Close()
}

func (p *DuplexPipeEnd) CloseWrite() error {
	return p.w.Close()
}

func (p *DuplexPipeEnd) Close() error {
	rerr := p.r.Close()
	werr := p.w.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

package zerocopy

import (
	"io"
)

// Reader provides a stream interface for reading.
type Reader interface {
	Headroom

	// MinimumPayloadBufferSize returns the minimum size of payload buffer
	// the ReadZeroCopy method requires.
	//
	// This is usually required by chunk-based protocols to be able to read
	// whole chunks without needing internal caching.
	MinimumPayloadBufferSize() int

	// ReadZeroCopy uses b as buffer space to initiate a read operation.
	//
	// b must have at least FrontOverhead() bytes before payloadBufStart
	// and RearOverhead() bytes after payloadBufStart + payloadBufLen.
	//
	// The read operation may use the whole space of b.
	// The actual payload will be confined in [payloadBufStart, payloadBufLen).
	//
	// If no error occurs, the returned payload is b[payloadBufStart : payloadBufStart+payloadLen].
	ReadZeroCopy(b []byte, payloadBufStart, payloadBufLen int) (payloadLen int, err error)
}

// Writer provides a stream interface for writing.
type Writer interface {
	Headroom

	// MaximumPayloadBufferSize returns the maximum size of payload buffer
	// the WriteZeroCopy method can accept.
	//
	// This is usually required by chunk-based protocols to be able to write
	// one chunk at a time without needing to break up the payload.
	//
	// If there isn't a maximum limit, return 0.
	MaximumPayloadBufferSize() int

	// WriteZeroCopy uses b as buffer space to initiate a write operation.
	//
	// b must have at least FrontOverhead() bytes before payloadBufStart
	// and RearOverhead() bytes after payloadBufStart + payloadBufLen.
	//
	// The write operation may use the whole space of b.
	WriteZeroCopy(b []byte, payloadStart, payloadLen int) (payloadWritten int, err error)
}

// DirectReader provides access to the underlying io.Reader.
type DirectReader interface {
	// DirectReader returns the underlying reader for direct reads.
	DirectReader() io.Reader
}

// DirectWriter provides access to the underlying io.Writer.
type DirectWriter interface {
	// DirectWriter returns the underlying writer for direct writes.
	DirectWriter() io.Writer
}

// Relay reads from r and writes to w using zero-copy methods.
// It returns the number of bytes transferred, and any error occurred during transfer.
func Relay(w Writer, r Reader) (n int64, err error) {
	// Use direct read/write when possible.
	if dr, ok := r.(DirectReader); ok {
		if dw, ok := w.(DirectWriter); ok {
			r := dr.DirectReader()
			w := dw.DirectWriter()
			n, err = io.Copy(w, r)
			return
		}
	}

	// Determine front headroom.
	frontHeadroom := r.FrontHeadroom()
	wfh := w.FrontHeadroom()
	if wfh > frontHeadroom {
		frontHeadroom = wfh
	}

	// Determine rear headroom.
	rearHeadroom := r.RearHeadroom()
	wrh := w.RearHeadroom()
	if wrh > rearHeadroom {
		rearHeadroom = wrh
	}

	// Check payload buffer size requirement compatibility.
	minPayloadBufSize := r.MinimumPayloadBufferSize()
	maxPayloadBufSize := w.MaximumPayloadBufferSize()
	if maxPayloadBufSize == 0 {
		maxPayloadBufSize = minPayloadBufSize
		if maxPayloadBufSize == 0 {
			maxPayloadBufSize = 32768 // The same default buffer size as io.Copy.
		}
	}
	if minPayloadBufSize > maxPayloadBufSize {
		return relayFallback(w, r, frontHeadroom, rearHeadroom, minPayloadBufSize, maxPayloadBufSize)
	}

	// Make buffer.
	b := make([]byte, frontHeadroom+maxPayloadBufSize+rearHeadroom)

	// Main relay loop.
	for {
		var payloadLen int
		payloadLen, err = r.ReadZeroCopy(b, frontHeadroom, maxPayloadBufSize)
		if payloadLen == 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}

		payloadWritten, werr := w.WriteZeroCopy(b, frontHeadroom, payloadLen)
		n += int64(payloadWritten)
		if werr != nil {
			err = werr
		}

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

// relayFallback uses copying to handle situations where the reader requires more payload buffer space than the writer can handle in one write call.
func relayFallback(w Writer, r Reader, frontHeadroom, rearHeadroom, readPayloadBufSize, writePayloadBufSize int) (n int64, err error) {
	br := make([]byte, frontHeadroom+readPayloadBufSize+rearHeadroom)
	bw := make([]byte, frontHeadroom+writePayloadBufSize+rearHeadroom)

	for {
		var payloadLen int
		payloadLen, err = r.ReadZeroCopy(br, frontHeadroom, readPayloadBufSize)
		if payloadLen == 0 {
			if err == io.EOF {
				err = nil
			}
			return
		}

		// Short-circuit to avoid copying if payload can fit in one write.
		if payloadLen <= writePayloadBufSize {
			payloadWritten, werr := w.WriteZeroCopy(br, frontHeadroom, payloadLen)
			n += int64(payloadWritten)
			if werr != nil {
				err = werr
			}
			if err != nil {
				return
			}
			continue
		}

		// Loop until all of br[frontHeadroom : frontHeadroom+payloadLen] is written.
		for i, j := 0, 0; i < payloadLen; i += j {
			j = copy(bw[frontHeadroom:frontHeadroom+writePayloadBufSize], br[frontHeadroom+i:frontHeadroom+payloadLen])
			payloadWritten, werr := w.WriteZeroCopy(bw, frontHeadroom, j)
			n += int64(payloadWritten)
			if werr != nil {
				err = werr
				break
			}
		}

		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

// ReadWriter provides a stream interface for reading and writing.
type ReadWriter interface {
	Reader
	Writer
}

// TwoWayRelay relays data between left and right using zero-copy methods.
// It returns the number of bytes sent from left to right, from right to left,
// and any error occurred during transfer.
func TwoWayRelay(left, right ReadWriter) (nl2r, nr2l int64, err error) {
	var l2rErr error
	ctrlCh := make(chan struct{})

	go func() {
		nl2r, l2rErr = Relay(right, left)
		ctrlCh <- struct{}{}
	}()

	nr2l, err = Relay(left, right)
	<-ctrlCh

	if l2rErr != nil {
		err = l2rErr
	}
	return
}

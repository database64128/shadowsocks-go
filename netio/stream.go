package netio

import (
	"errors"
	"io"
	"net"
	"sync"
)

// Reader is an alias for [io.Reader].
type Reader = io.Reader

// Writer is [io.Writer] with CloseWrite.
type Writer interface {
	io.Writer

	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

// ReadWriter is [io.ReadWriter] with CloseWrite.
type ReadWriter interface {
	Reader
	Writer
}

// BidirectionalCopy copies data between two ReadWriters in both directions,
// until either EOF is reached or an error occurs, after which it closes the
// writing side of the receiving ReadWriter.
//
// It returns the number of bytes copied in each direction, and all errors
// encountered during the copy wrapped together.
func BidirectionalCopy(left, right ReadWriter) (nl2r, nr2l int64, err error) {
	var (
		wg     sync.WaitGroup
		l2rErr error
	)

	wg.Add(1)
	go func() {
		nl2r, l2rErr = io.Copy(right, left)
		_ = right.CloseWrite()
		wg.Done()
	}()

	nr2l, err = io.Copy(left, right)
	_ = left.CloseWrite()
	wg.Wait()

	return nl2r, nr2l, errors.Join(l2rErr, err)
}

// Conn is [net.Conn] with CloseWrite.
type Conn interface {
	net.Conn

	// CloseWrite shuts down the writing side of the connection.
	CloseWrite() error
}

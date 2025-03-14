package netio_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/netio"
	"golang.org/x/net/nettest"
)

func TestPipe(t *testing.T) {
	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		c1, c2 = netio.NewPipe()
		stop = func() {
			c1.Close()
			c2.Close()
		}
		return
	})
}

var (
	errTest1 = errors.New("errTest1")
	errTest2 = errors.New("errTest2")
)

func TestPipeWriteTo(t *testing.T) {
	for _, c := range []struct {
		name            string
		payload         [3][]byte
		expectedBytes   []byte
		readDeadline    time.Time
		closeReadError  error
		closeWriteError error
		expectedError   error
	}{
		{
			name: "NoError",
			payload: [3][]byte{
				[]byte("Hello, "),
				[]byte("world!"),
				[]byte("\n"),
			},
			expectedBytes: []byte("Hello, world!\n"),
		},
		{
			name: "ReadDeadline",
			payload: [3][]byte{
				[]byte("Hello, "),
				[]byte("world!"),
				[]byte("\n"),
			},
			expectedBytes: []byte("Hello, "),
			readDeadline:  time.Unix(0, 0),
			expectedError: os.ErrDeadlineExceeded,
		},
		{
			name: "CloseReadError",
			payload: [3][]byte{
				[]byte("Hello, "),
				[]byte("world!"),
				[]byte("\n"),
			},
			expectedBytes:  []byte("Hello, "),
			closeReadError: errTest1,
			expectedError:  errTest1,
		},
		{
			name: "CloseWriteError",
			payload: [3][]byte{
				[]byte("Hello, "),
				[]byte("world!"),
				[]byte("\n"),
			},
			expectedBytes:   []byte("Hello, world!"),
			closeWriteError: errTest2,
			expectedError:   errTest2,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			c1, c2 := netio.NewPipe()

			var wg sync.WaitGroup
			defer wg.Wait()
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c1.Write(c.payload[0]); err != nil {
					t.Errorf("c1.Write(c.payload[0]) failed: %v", err)
					return
				}
				if !c.readDeadline.IsZero() {
					if err := c2.SetReadDeadline(c.readDeadline); err != nil {
						t.Errorf("c1.SetReadDeadline() failed: %v", err)
					}
					return
				}
				if c.closeReadError != nil {
					c2.CloseReadWithError(c.closeReadError)
					return
				}
				if _, err := c1.Write(c.payload[1]); err != nil {
					t.Errorf("c1.Write(c.payload[1]) failed: %v", err)
					return
				}
				if c.closeWriteError != nil {
					c1.CloseWriteWithError(c.closeWriteError)
					return
				}
				if _, err := c1.Write(c.payload[2]); err != nil {
					t.Errorf("c1.Write(c.payload[2]) failed: %v", err)
					return
				}
				if err := c1.CloseWrite(); err != nil {
					t.Errorf("c1.CloseWrite() failed: %v", err)
					return
				}
			}()

			var buf bytes.Buffer
			buf.Grow(len(c.expectedBytes))
			n, err := c2.WriteTo(&buf)
			if n != int64(len(c.expectedBytes)) || !errors.Is(err, c.expectedError) {
				t.Errorf("c2.WriteTo() = (%d, %v), want (%d, %v)", n, err, len(c.expectedBytes), c.expectedError)
			}
			if got := buf.Bytes(); !bytes.Equal(got, c.expectedBytes) {
				t.Errorf("buf.Bytes() = %v, want %v", got, c.expectedBytes)
			}
		})
	}
}

func readHelloWorld(t *testing.T, c *netio.PipeConn) {
	t.Helper()
	b := make([]byte, 16)
	want := []byte("Hello, world!")
	n, err := c.Read(b)
	if n != len(want) || err != nil {
		t.Errorf("c.Read() = (%d, %v), want (%d, nil)", n, err, len(want))
	}
	if got := b[:n]; !bytes.Equal(got, want) {
		t.Errorf("b[:n] = %v, want %v", got, want)
	}
}

func TestPipeCloseRead(t *testing.T) {
	c1, c2 := netio.NewPipe()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(2)
	go func() {
		defer wg.Done()
		readHelloWorld(t, c2)
	}()
	go func() {
		defer wg.Done()
		if _, err := c2.Write(nil); err != io.ErrClosedPipe {
			t.Errorf("c2.Write() = %v, want io.ErrClosedPipe", err)
		}
	}()

	if err := c1.CloseRead(); err != nil {
		t.Errorf("c1.CloseRead() = %v, want nil", err)
	}
	if _, err := c1.Read(nil); err != io.ErrClosedPipe {
		t.Errorf("c1.Read() = %v, want io.ErrClosedPipe", err)
	}
	if _, err := c1.WriteTo(nil); err != io.ErrClosedPipe {
		t.Errorf("c1.WriteTo() = %v, want io.ErrClosedPipe", err)
	}
	if _, err := c1.Write([]byte("Hello, world!")); err != nil {
		t.Errorf("c1.Write() = %v, want nil", err)
	}
}

func TestPipeCloseWrite(t *testing.T) {
	c1, c2 := netio.NewPipe()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := c2.Read(nil); err != io.EOF {
			t.Errorf("c2.Read() = %v, want io.EOF", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := c2.Write([]byte("Hello, world!")); err != nil {
			t.Errorf("c2.Write() = %v, want nil", err)
		}
	}()

	if err := c1.CloseWrite(); err != nil {
		t.Errorf("c1.CloseWrite() = %v, want nil", err)
	}
	if _, err := c1.Write(nil); err != io.ErrClosedPipe {
		t.Errorf("c1.Write() = %v, want io.ErrClosedPipe", err)
	}
	readHelloWorld(t, c1)
}

func TestPipeClose(t *testing.T) {
	c1, c2 := netio.NewPipe()

	if err := c1.Close(); err != nil {
		t.Errorf("c1.Close() = %v, want nil", err)
	}
	if _, err := c1.Read(nil); err != io.ErrClosedPipe {
		t.Errorf("c1.Read() = %v, want io.ErrClosedPipe", err)
	}
	if _, err := c1.Write(nil); err != io.ErrClosedPipe {
		t.Errorf("c1.Write() = %v, want io.ErrClosedPipe", err)
	}
	if err := c1.SetDeadline(time.Time{}); err != io.ErrClosedPipe {
		t.Errorf("c1.SetDeadline() = %v, want io.ErrClosedPipe", err)
	}
	if _, err := c2.Read(nil); err != io.EOF {
		t.Errorf("c2.Read() = %v, want io.EOF", err)
	}
	if _, err := c2.Write(nil); err != io.ErrClosedPipe {
		t.Errorf("c2.Write() = %v, want io.ErrClosedPipe", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		t.Errorf("c2.SetDeadline() = %v, want nil", err)
	}
}

func TestPipeCloseWithError(t *testing.T) {
	c1, c2 := netio.NewPipe()
	wantTestError1 := func() {
		t.Helper()
		if _, err := c1.Write(nil); !errors.Is(err, errTest1) {
			t.Errorf("c1.Write() = %v, want errTest1", err)
		}
		if _, err := c2.Read(nil); !errors.Is(err, errTest1) {
			t.Errorf("c2.Read() = %v, want errTest1", err)
		}
	}
	wantTestError2 := func() {
		t.Helper()
		if _, err := c1.Read(nil); !errors.Is(err, errTest2) {
			t.Errorf("c1.Read() = %v, want errTest2", err)
		}
		if _, err := c2.Write(nil); !errors.Is(err, errTest2) {
			t.Errorf("c2.Write() = %v, want errTest2", err)
		}
	}

	c1.CloseWriteWithError(errTest1)
	wantTestError1()
	c1.CloseWriteWithError(errTest2)
	wantTestError1()
	c2.CloseReadWithError(errTest2)
	wantTestError1()

	c1.CloseReadWithError(errTest2)
	wantTestError2()
	c1.CloseReadWithError(errTest1)
	wantTestError2()
	c2.CloseWriteWithError(errTest1)
	wantTestError2()
}

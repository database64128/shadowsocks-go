//go:build linux || netbsd

package conn

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

// MmsgConn wraps a [net.UDPConn] and provides additional methods that
// utilize the recvmmsg(2) and sendmmsg(2) system calls for batch I/O.
type MmsgConn struct {
	*net.UDPConn
	readMsgvec   []Mmsghdr
	writeMsgvec  []Mmsghdr
	readFlags    int
	writeFlags   int
	readN        int
	readErr      error
	writeErr     error
	rawConn      syscall.RawConn
	rawReadFunc  func(fd uintptr) (done bool)
	rawWriteFunc func(fd uintptr) (done bool)
}

// NewMmsgConn returns a new [MmsgConn] that wraps the given [net.UDPConn].
func NewMmsgConn(udpConn *net.UDPConn) (*MmsgConn, error) {
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	mmsgConn := MmsgConn{
		UDPConn: udpConn,
		rawConn: rawConn,
	}

	mmsgConn.rawReadFunc = func(fd uintptr) (done bool) {
		var errno syscall.Errno
		mmsgConn.readN, errno = recvmmsg(int(fd), mmsgConn.readMsgvec, mmsgConn.readFlags)
		switch errno {
		case 0:
		case syscall.EAGAIN:
			return false
		default:
			mmsgConn.readErr = os.NewSyscallError("recvmmsg", errno)
		}
		return true
	}

	mmsgConn.rawWriteFunc = func(fd uintptr) (done bool) {
		n, errno := sendmmsg(int(fd), mmsgConn.writeMsgvec, mmsgConn.writeFlags)
		switch errno {
		case 0:
		case syscall.EAGAIN:
			return false
		default:
			mmsgConn.writeErr = os.NewSyscallError("sendmmsg", errno)
			n = 1
		}
		mmsgConn.writeMsgvec = mmsgConn.writeMsgvec[n:]
		// According to tokio, not writing the full msgvec is sufficient to show
		// that the socket buffer is full. Previous tests also showed that this is
		// faster than immediately trying to write again.
		//
		// Do keep in mind that this is not how the Go runtime handles writes though.
		return len(mmsgConn.writeMsgvec) == 0
	}

	return &mmsgConn, nil
}

// ReadMsgs reads as many messages as possible into the given msgvec
// and returns the number of messages read or an error.
func (c *MmsgConn) ReadMsgs(msgvec []Mmsghdr, flags int) (int, error) {
	c.readMsgvec = msgvec
	c.readFlags = flags
	c.readN = 0
	c.readErr = nil
	if err := c.rawConn.Read(c.rawReadFunc); err != nil {
		return 0, err
	}
	return c.readN, c.readErr
}

// WriteMsgs writes all messages in the given msgvec and returns the last encountered error.
func (c *MmsgConn) WriteMsgs(msgvec []Mmsghdr, flags int) error {
	c.writeMsgvec = msgvec
	c.writeFlags = flags
	c.writeErr = nil
	if err := c.rawConn.Write(c.rawWriteFunc); err != nil {
		return err
	}
	return c.writeErr
}

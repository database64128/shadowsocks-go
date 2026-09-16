//go:build !plan9

package conn

import (
	"errors"
	"syscall"
)

func dialResultCodeFromSyscallError(err error) (DialResultCode, bool) {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return dialResultCodeFromSyscallErrno(errno), true
	}
	return 0, false
}

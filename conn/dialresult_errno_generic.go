//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !plan9 && !solaris && !windows && !zos

package conn

import "syscall"

func dialResultCodeFromSyscallErrno(e syscall.Errno) DialResultCode {
	switch e {
	case 0:
		return DialResultCodeSuccess
	default:
		return DialResultCodeErrOther
	}
}

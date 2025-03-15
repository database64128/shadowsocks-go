//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

import "golang.org/x/sys/unix"

func dialResultCodeFromSyscallErrno(e unix.Errno) DialResultCode {
	switch e {
	case 0:
		return DialResultCodeSuccess
	case unix.EACCES:
		return DialResultCodeEACCES
	case unix.ENETDOWN:
		return DialResultCodeENETDOWN
	case unix.ENETUNREACH:
		return DialResultCodeENETUNREACH
	case unix.ENETRESET:
		return DialResultCodeENETRESET
	case unix.ECONNABORTED:
		return DialResultCodeECONNABORTED
	case unix.ECONNRESET:
		return DialResultCodeECONNRESET
	case unix.ETIMEDOUT:
		return DialResultCodeETIMEDOUT
	case unix.ECONNREFUSED:
		return DialResultCodeECONNREFUSED
	case unix.EHOSTDOWN:
		return DialResultCodeEHOSTDOWN
	case unix.EHOSTUNREACH:
		return DialResultCodeEHOSTUNREACH
	default:
		return DialResultCodeErrOther
	}
}

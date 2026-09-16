//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !plan9 && !solaris && !windows && !zos

package conn

import "syscall"

func dialResultCodeFromSyscallErrno(e syscall.Errno) DialResultCode {
	switch e {
	case 0:
		return DialResultCodeSuccess
	case syscall.EACCES:
		return DialResultCodeEACCES
	case syscall.ENETDOWN:
		return DialResultCodeENETDOWN
	case syscall.ENETUNREACH:
		return DialResultCodeENETUNREACH
	case syscall.ENETRESET:
		return DialResultCodeENETRESET
	case syscall.ECONNABORTED:
		return DialResultCodeECONNABORTED
	case syscall.ECONNRESET:
		return DialResultCodeECONNRESET
	case syscall.ETIMEDOUT:
		return DialResultCodeETIMEDOUT
	case syscall.ECONNREFUSED:
		return DialResultCodeECONNREFUSED
	case syscall.EHOSTDOWN:
		return DialResultCodeEHOSTDOWN
	case syscall.EHOSTUNREACH:
		return DialResultCodeEHOSTUNREACH
	default:
		return DialResultCodeErrOther
	}
}

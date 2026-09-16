package conn

import (
	"errors"
	"syscall"
)

func dialResultCodeFromSyscallError(err error) (DialResultCode, bool) {
	if e, ok := errors.AsType[syscall.ErrorString](err); ok {
		return dialResultCodeFromSyscallErrorString(e), true
	}
	return 0, false
}

func dialResultCodeFromSyscallErrorString(e syscall.ErrorString) DialResultCode {
	switch e {
	case syscall.ETIMEDOUT:
		return DialResultCodeETIMEDOUT
	default:
		return DialResultCodeErrOther
	}
}

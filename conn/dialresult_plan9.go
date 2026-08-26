package conn

import (
	"errors"
	"net"
	"syscall"
)

func dialResultCodeFromError(err error) DialResultCode {
	if err == nil {
		return DialResultCodeSuccess
	}
	if e, ok := errors.AsType[syscall.ErrorString](err); ok {
		return dialResultCodeFromSyscallErrorString(e)
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return DialResultCodeErrDomainNameLookup
	}
	return DialResultCodeErrOther
}

func dialResultCodeFromSyscallErrorString(e syscall.ErrorString) DialResultCode {
	switch e {
	case syscall.ETIMEDOUT:
		return DialResultCodeETIMEDOUT
	default:
		return DialResultCodeErrOther
	}
}

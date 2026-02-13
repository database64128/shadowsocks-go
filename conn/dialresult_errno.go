//go:build !plan9

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
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return dialResultCodeFromSyscallErrno(errno)
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return DialResultCodeErrDomainNameLookup
	}
	return DialResultCodeErrOther
}

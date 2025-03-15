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

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return dialResultCodeFromSyscallErrno(errno)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DialResultCodeErrDomainNameLookup
	}

	return DialResultCodeErrOther
}

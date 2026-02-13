package conn

import (
	"errors"
	"net"
)

func dialResultCodeFromError(err error) DialResultCode {
	if err == nil {
		return DialResultCodeSuccess
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return DialResultCodeErrDomainNameLookup
	}
	return DialResultCodeErrOther
}

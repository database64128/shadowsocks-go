package conn

import (
	"errors"
	"net"
)

func dialResultCodeFromError(err error) DialResultCode {
	if err == nil {
		return DialResultCodeSuccess
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DialResultCodeErrDomainNameLookup
	}

	return DialResultCodeErrOther
}

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !plan9 && !solaris && !windows && !zos

package conn

import (
	"net"
	"syscall"
)

var dialResultTestCases = [...]dialResultTestCase{
	{
		name:                   "Success",
		err:                    nil,
		expectedDialResultCode: DialResultCodeSuccess,
	},
	{
		name:                   "Errno(1)",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: syscall.Errno(1)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "ErrDomainNameLookup",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		name:                   "ErrOther",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
		expectedDialResultCode: DialResultCodeErrOther,
	},
}

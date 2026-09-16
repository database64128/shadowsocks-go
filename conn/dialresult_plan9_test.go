package conn

import (
	"net"
	"os"
	"syscall"
)

var dialResultTestCases = [...]dialResultTestCase{
	{
		name:                   "Success",
		err:                    nil,
		expectedDialResultCode: DialResultCodeSuccess,
	},
	{
		name:                   "aclError",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: aclError{}},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "syscall.ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "*net.DNSError/NilUnwrap",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		// See the note in dialresult_unix_test.go
		name:                   "*net.DNSError/syscall.ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{UnwrapErr: os.NewSyscallError("connect", syscall.ETIMEDOUT), Err: "connection timed out"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		name:                   "*net.AddrError",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
		expectedDialResultCode: DialResultCodeErrOther,
	},
}

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !plan9 && !solaris && !windows && !zos

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
		name:                   "syscall.EACCES",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.EACCES)},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "syscall.EINVAL",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.EINVAL)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "syscall.ENETDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ENETDOWN)},
		expectedDialResultCode: DialResultCodeENETDOWN,
	},
	{
		name:                   "syscall.ENETUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ENETUNREACH)},
		expectedDialResultCode: DialResultCodeENETUNREACH,
	},
	{
		name:                   "syscall.ENETRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ENETRESET)},
		expectedDialResultCode: DialResultCodeENETRESET,
	},
	{
		name:                   "syscall.ECONNABORTED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ECONNABORTED)},
		expectedDialResultCode: DialResultCodeECONNABORTED,
	},
	{
		name:                   "syscall.ECONNRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ECONNRESET)},
		expectedDialResultCode: DialResultCodeECONNRESET,
	},
	{
		name:                   "syscall.ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "syscall.ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		expectedDialResultCode: DialResultCodeECONNREFUSED,
	},
	{
		name:                   "syscall.EHOSTDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.EHOSTDOWN)},
		expectedDialResultCode: DialResultCodeEHOSTDOWN,
	},
	{
		name:                   "syscall.EHOSTUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)},
		expectedDialResultCode: DialResultCodeEHOSTUNREACH,
	},
	{
		name:                   "*net.DNSError/NilUnwrap",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		// See the note in dialresult_unix_test.go
		name:                   "*net.DNSError/syscall.ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{UnwrapErr: os.NewSyscallError("connect", syscall.ECONNREFUSED), Err: "connection refused"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		name:                   "*net.AddrError",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
		expectedDialResultCode: DialResultCodeErrOther,
	},
}

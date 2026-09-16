//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
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
		name:                   "unix.EACCES",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EACCES)},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "unix.EINVAL",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EINVAL)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "unix.ENETDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETDOWN)},
		expectedDialResultCode: DialResultCodeENETDOWN,
	},
	{
		name:                   "unix.ENETUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETUNREACH)},
		expectedDialResultCode: DialResultCodeENETUNREACH,
	},
	{
		name:                   "unix.ENETRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETRESET)},
		expectedDialResultCode: DialResultCodeENETRESET,
	},
	{
		name:                   "unix.ECONNABORTED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNABORTED)},
		expectedDialResultCode: DialResultCodeECONNABORTED,
	},
	{
		name:                   "unix.ECONNRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNRESET)},
		expectedDialResultCode: DialResultCodeECONNRESET,
	},
	{
		name:                   "unix.ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "unix.ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNREFUSED)},
		expectedDialResultCode: DialResultCodeECONNREFUSED,
	},
	{
		name:                   "unix.EHOSTDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EHOSTDOWN)},
		expectedDialResultCode: DialResultCodeEHOSTDOWN,
	},
	{
		name:                   "unix.EHOSTUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EHOSTUNREACH)},
		expectedDialResultCode: DialResultCodeEHOSTUNREACH,
	},
	{
		name:                   "*net.DNSError/NilUnwrap",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		// The std net package won't actually return a [*net.DNSError] with a wrapped syscall error.
		// It only ever wraps context errors. See https://github.com/golang/go/issues/63116.
		// We include this test case anyway to ensure correct behavior.
		name:                   "*net.DNSError/unix.ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{UnwrapErr: os.NewSyscallError("connect", unix.ECONNREFUSED), Err: "connection refused"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		name:                   "*net.AddrError",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
		expectedDialResultCode: DialResultCodeErrOther,
	},
}

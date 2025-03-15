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
		name:                   "EACCES",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EACCES)},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "EINVAL",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EINVAL)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "ENETDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETDOWN)},
		expectedDialResultCode: DialResultCodeENETDOWN,
	},
	{
		name:                   "ENETUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETUNREACH)},
		expectedDialResultCode: DialResultCodeENETUNREACH,
	},
	{
		name:                   "ENETRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ENETRESET)},
		expectedDialResultCode: DialResultCodeENETRESET,
	},
	{
		name:                   "ECONNABORTED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNABORTED)},
		expectedDialResultCode: DialResultCodeECONNABORTED,
	},
	{
		name:                   "ECONNRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNRESET)},
		expectedDialResultCode: DialResultCodeECONNRESET,
	},
	{
		name:                   "ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.ECONNREFUSED)},
		expectedDialResultCode: DialResultCodeECONNREFUSED,
	},
	{
		name:                   "EHOSTDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EHOSTDOWN)},
		expectedDialResultCode: DialResultCodeEHOSTDOWN,
	},
	{
		name:                   "EHOSTUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", unix.EHOSTUNREACH)},
		expectedDialResultCode: DialResultCodeEHOSTUNREACH,
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

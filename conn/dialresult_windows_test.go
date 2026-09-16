package conn

import (
	"net"
	"os"

	"golang.org/x/sys/windows"
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
		name:                   "windows.WSAEACCES",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEACCES)},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "windows.WSAEINVAL",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEINVAL)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "windows.WSAENETDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETDOWN)},
		expectedDialResultCode: DialResultCodeENETDOWN,
	},
	{
		name:                   "windows.WSAENETUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETUNREACH)},
		expectedDialResultCode: DialResultCodeENETUNREACH,
	},
	{
		name:                   "windows.WSAENETRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETRESET)},
		expectedDialResultCode: DialResultCodeENETRESET,
	},
	{
		name:                   "windows.WSAECONNABORTED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNABORTED)},
		expectedDialResultCode: DialResultCodeECONNABORTED,
	},
	{
		name:                   "windows.WSAECONNRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNRESET)},
		expectedDialResultCode: DialResultCodeECONNRESET,
	},
	{
		name:                   "windows.WSAETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "windows.WSAECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNREFUSED)},
		expectedDialResultCode: DialResultCodeECONNREFUSED,
	},
	{
		name:                   "windows.WSAEHOSTDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEHOSTDOWN)},
		expectedDialResultCode: DialResultCodeEHOSTDOWN,
	},
	{
		name:                   "windows.WSAEHOSTUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEHOSTUNREACH)},
		expectedDialResultCode: DialResultCodeEHOSTUNREACH,
	},
	{
		name:                   "*net.DNSError/NilUnwrap",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{Err: "no such host"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		// See the note in dialresult_unix_test.go
		name:                   "*net.DNSError/windows.WSAECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.DNSError{UnwrapErr: os.NewSyscallError("connect", windows.WSAECONNREFUSED), Err: "connection refused"}},
		expectedDialResultCode: DialResultCodeErrDomainNameLookup,
	},
	{
		name:                   "*net.AddrError",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: &net.AddrError{Err: "mismatched local address type"}},
		expectedDialResultCode: DialResultCodeErrOther,
	},
}

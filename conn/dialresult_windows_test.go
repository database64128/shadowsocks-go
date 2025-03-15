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
		name:                   "EACCES",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEACCES)},
		expectedDialResultCode: DialResultCodeEACCES,
	},
	{
		name:                   "EINVAL",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEINVAL)},
		expectedDialResultCode: DialResultCodeErrOther,
	},
	{
		name:                   "ENETDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETDOWN)},
		expectedDialResultCode: DialResultCodeENETDOWN,
	},
	{
		name:                   "ENETUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETUNREACH)},
		expectedDialResultCode: DialResultCodeENETUNREACH,
	},
	{
		name:                   "ENETRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAENETRESET)},
		expectedDialResultCode: DialResultCodeENETRESET,
	},
	{
		name:                   "ECONNABORTED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNABORTED)},
		expectedDialResultCode: DialResultCodeECONNABORTED,
	},
	{
		name:                   "ECONNRESET",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNRESET)},
		expectedDialResultCode: DialResultCodeECONNRESET,
	},
	{
		name:                   "ETIMEDOUT",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAETIMEDOUT)},
		expectedDialResultCode: DialResultCodeETIMEDOUT,
	},
	{
		name:                   "ECONNREFUSED",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAECONNREFUSED)},
		expectedDialResultCode: DialResultCodeECONNREFUSED,
	},
	{
		name:                   "EHOSTDOWN",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEHOSTDOWN)},
		expectedDialResultCode: DialResultCodeEHOSTDOWN,
	},
	{
		name:                   "EHOSTUNREACH",
		err:                    &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: os.NewSyscallError("connect", windows.WSAEHOSTUNREACH)},
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

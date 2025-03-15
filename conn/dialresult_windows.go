package conn

import "golang.org/x/sys/windows"

func dialResultCodeFromSyscallErrno(e windows.Errno) DialResultCode {
	switch e {
	case 0:
		return DialResultCodeSuccess
	case windows.WSAEACCES:
		return DialResultCodeEACCES
	case windows.WSAENETDOWN:
		return DialResultCodeENETDOWN
	case windows.WSAENETUNREACH:
		return DialResultCodeENETUNREACH
	case windows.WSAENETRESET:
		return DialResultCodeENETRESET
	case windows.WSAECONNABORTED:
		return DialResultCodeECONNABORTED
	case windows.WSAECONNRESET:
		return DialResultCodeECONNRESET
	case windows.WSAETIMEDOUT:
		return DialResultCodeETIMEDOUT
	case windows.WSAECONNREFUSED:
		return DialResultCodeECONNREFUSED
	case windows.WSAEHOSTDOWN:
		return DialResultCodeEHOSTDOWN
	case windows.WSAEHOSTUNREACH:
		return DialResultCodeEHOSTUNREACH
	default:
		return DialResultCodeErrOther
	}
}

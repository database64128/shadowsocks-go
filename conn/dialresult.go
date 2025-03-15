package conn

// DialResultCode is the result code of a dial operation.
type DialResultCode uint8

const (
	DialResultCodeSuccess DialResultCode = 0 // success

	// Based on Linux errno values.
	DialResultCodeEACCES       DialResultCode = 13  // EACCES       WSAEACCES       "permission denied" (denied by policy)
	DialResultCodeENETDOWN     DialResultCode = 100 // ENETDOWN     WSAENETDOWN     "network is down"
	DialResultCodeENETUNREACH  DialResultCode = 101 // ENETUNREACH  WSAENETUNREACH  "network is unreachable"
	DialResultCodeENETRESET    DialResultCode = 102 // ENETRESET    WSAENETRESET    "network dropped connection on reset"
	DialResultCodeECONNABORTED DialResultCode = 103 // ECONNABORTED WSAECONNABORTED "software caused connection abort"
	DialResultCodeECONNRESET   DialResultCode = 104 // ECONNRESET   WSAECONNRESET   "connection reset by peer"
	DialResultCodeETIMEDOUT    DialResultCode = 110 // ETIMEDOUT    WSAETIMEDOUT    "connection timed out"
	DialResultCodeECONNREFUSED DialResultCode = 111 // ECONNREFUSED WSAECONNREFUSED "connection refused"
	DialResultCodeEHOSTDOWN    DialResultCode = 112 // EHOSTDOWN    WSAEHOSTDOWN    "host is down" (ICMPv4-only)
	DialResultCodeEHOSTUNREACH DialResultCode = 113 // EHOSTUNREACH WSAEHOSTUNREACH "no route to host"

	DialResultCodeErrDomainNameLookup DialResultCode = 254 // domain name lookup error
	DialResultCodeErrOther            DialResultCode = 255 // other error
)

// DialResultCodeFromError parses the error and returns a [DialResultCode].
func DialResultCodeFromError(err error) DialResultCode {
	return dialResultCodeFromError(err)
}

// String returns the string representation of the dial result code.
func (c DialResultCode) String() string {
	switch c {
	case DialResultCodeSuccess:
		return "success"
	case DialResultCodeEACCES:
		return "permission denied"
	case DialResultCodeENETDOWN:
		return "network is down"
	case DialResultCodeENETUNREACH:
		return "network is unreachable"
	case DialResultCodeENETRESET:
		return "network dropped connection on reset"
	case DialResultCodeECONNABORTED:
		return "software caused connection abort"
	case DialResultCodeECONNRESET:
		return "connection reset by peer"
	case DialResultCodeETIMEDOUT:
		return "connection timed out"
	case DialResultCodeECONNREFUSED:
		return "connection refused"
	case DialResultCodeEHOSTDOWN:
		return "host is down"
	case DialResultCodeEHOSTUNREACH:
		return "no route to host"
	case DialResultCodeErrDomainNameLookup:
		return "domain name lookup error"
	case DialResultCodeErrOther:
		return "other error"
	default:
		return "unknown error"
	}
}

// DialResult contains the result of a dial operation.
type DialResult struct {
	// Code is the result code of the dial operation.
	Code DialResultCode

	// Err is the error returned by the dial operation.
	Err error
}

// DialResultFromError parses the error and returns a [DialResult].
func DialResultFromError(err error) DialResult {
	return DialResult{
		Code: DialResultCodeFromError(err),
		Err:  err,
	}
}

// String returns the string representation of the dial result.
func (r DialResult) String() string {
	s := r.Code.String()
	if r.Err != nil {
		s += ": " + r.Err.Error()
	}
	return s
}

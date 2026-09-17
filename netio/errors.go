package netio

import (
	"net/netip"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
)

// OpError represents a network operation error.
type OpError struct {
	// Op is the name of the operation that caused the error,
	// such as "dial", "read", or "write".
	Op string

	// Network is the network type,
	// such as "tcp" or "udp".
	Network string

	// LocalAddrPort is the local address of the connection.
	LocalAddrPort netip.AddrPort

	// RemoteAddrPort is the remote address of the connection.
	RemoteAddrPort netip.AddrPort

	// Err is the underlying error that occurred during the network operation.
	Err error
}

func (e *OpError) Error() string {
	// IPv6 addresses with zone are in fe80::/64, which we should have enough space for.
	const addrCap = len("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
	err := e.Err.Error()
	capacity := len(e.Op) + 1 + len(e.Network) + 1 + addrCap + 2 + len(err)
	if e.LocalAddrPort.IsValid() {
		capacity += addrCap + 2
	}
	b := make([]byte, 0, capacity)
	b = append(b, e.Op...)
	b = append(b, ' ')
	b = append(b, e.Network...)
	b = append(b, ' ')
	if e.LocalAddrPort.IsValid() {
		b = e.LocalAddrPort.AppendTo(b)
		b = append(b, '-', '>')
	}
	b = e.RemoteAddrPort.AppendTo(b)
	b = append(b, ':', ' ')
	b = append(b, err...)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func (e *OpError) Unwrap() error {
	return e.Err
}

// AddrNotInAllowlistError is returned when the destination address is not in the allowlist.
type AddrNotInAllowlistError struct{}

func (AddrNotInAllowlistError) Error() string {
	return "address not in allowlist"
}

func (AddrNotInAllowlistError) Unwrap() error {
	return conn.DialResultCodeEACCES
}

// AddrInDenylistError is returned when the destination address is in the denylist.
type AddrInDenylistError struct{}

func (AddrInDenylistError) Error() string {
	return "address in denylist"
}

func (AddrInDenylistError) Unwrap() error {
	return conn.DialResultCodeEACCES
}

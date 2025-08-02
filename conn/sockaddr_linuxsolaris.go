//go:build linux || solaris

package conn

import (
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/unix"
)

func SockaddrPutAddrPort(name *unix.RawSockaddrInet6, namelen *uint32, addrPort netip.AddrPort) {
	if !addrPort.IsValid() {
		*name = unix.RawSockaddrInet6{}
		*namelen = 0
		return
	}
	addr, port := addrPort.Addr(), addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&name.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	if addr.Is4() {
		name.Family = unix.AF_INET
		a := (*[4]byte)(unsafe.Pointer(&name.Flowinfo))
		*a = addr.As4()
		*namelen = unix.SizeofSockaddrInet4
		return
	}
	name.Family = unix.AF_INET6
	name.Addr = addr.As16()
	name.Scope_id = uint32(netx.ZoneCache.Index(addr.Zone()))
	*namelen = unix.SizeofSockaddrInet6
}

func SockaddrInet4PutAddrPort(sa *unix.RawSockaddrInet4, addrPort netip.AddrPort) {
	sa.Family = unix.AF_INET
	port := addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	sa.Addr = addrPort.Addr().As4()
}

func SockaddrInet6PutAddrPort(sa *unix.RawSockaddrInet6, addrPort netip.AddrPort) {
	sa.Family = unix.AF_INET6
	port := addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	addr := addrPort.Addr()
	sa.Addr = addr.As16()
	sa.Scope_id = uint32(netx.ZoneCache.Index(addr.Zone()))
}

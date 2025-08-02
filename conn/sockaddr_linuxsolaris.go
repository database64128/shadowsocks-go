//go:build linux || solaris

package conn

import (
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/unix"
)

func AddrPortToSockaddrValue(addrPort netip.AddrPort) (rsa6 unix.RawSockaddrInet6, namelen uint32) {
	if !addrPort.IsValid() {
		return
	}
	addr, port := addrPort.Addr(), addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	if addr.Is4() {
		rsa6.Family = unix.AF_INET
		a := (*[4]byte)(unsafe.Pointer(&rsa6.Flowinfo))
		*a = addr.As4()
		namelen = unix.SizeofSockaddrInet4
		return
	}
	rsa6.Family = unix.AF_INET6
	rsa6.Addr = addr.As16()
	rsa6.Scope_id = uint32(netx.ZoneCache.Index(addr.Zone()))
	namelen = unix.SizeofSockaddrInet6
	return
}

func AddrPortToSockaddrInet4(addrPort netip.AddrPort) unix.RawSockaddrInet4 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa4 := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Addr:   addr.As4(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa4
}

func AddrPortToSockaddrInet6(addrPort netip.AddrPort) unix.RawSockaddrInet6 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa6 := unix.RawSockaddrInet6{
		Family:   unix.AF_INET6,
		Addr:     addr.As16(),
		Scope_id: uint32(netx.ZoneCache.Index(addr.Zone())),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

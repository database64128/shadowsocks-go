//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/unix"
)

func SockaddrValueToAddrPort(rsa6 unix.RawSockaddrInet6, namelen uint32) (netip.AddrPort, error) {
	if namelen == 0 {
		return netip.AddrPort{}, nil
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	port := uint16(p[0])<<8 + uint16(p[1])
	var addr netip.Addr
	switch namelen {
	case unix.SizeofSockaddrInet4:
		addr = netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&rsa6.Flowinfo)))
	case unix.SizeofSockaddrInet6:
		addr = netip.AddrFrom16(rsa6.Addr).WithZone(netx.ZoneCache.Name(int(rsa6.Scope_id)))
	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
	return netip.AddrPortFrom(addr, port), nil
}

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	switch {
	case !addrPort.IsValid():
		return nil, 0
	case addrPort.Addr().Is4():
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		return (*byte)(unsafe.Pointer(&rsa4)), unix.SizeofSockaddrInet4
	default:
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		return (*byte)(unsafe.Pointer(&rsa6)), unix.SizeofSockaddrInet6
	}
}

func AddrPortUnmappedToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	switch {
	case !addrPort.IsValid():
		return nil, 0
	case addrPort.Addr().Is4() || addrPort.Addr().Is4In6():
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		return (*byte)(unsafe.Pointer(&rsa4)), unix.SizeofSockaddrInet4
	default:
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		return (*byte)(unsafe.Pointer(&rsa6)), unix.SizeofSockaddrInet6
	}
}

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
	case 0:
		return netip.AddrPort{}, nil

	case unix.SizeofSockaddrInet4:
		rsa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
		return SockaddrInet4ToAddrPort(rsa4), nil

	case unix.SizeofSockaddrInet6:
		rsa6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(name))
		return SockaddrInet6ToAddrPort(rsa6), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
}

func SockaddrInet4ToAddrPort(sa *unix.RawSockaddrInet4) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom4(sa.Addr)
	return netip.AddrPortFrom(ip, port)
}

func SockaddrInet6ToAddrPort(sa *unix.RawSockaddrInet6) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom16(sa.Addr).WithZone(netx.ZoneCache.Name(int(sa.Scope_id)))
	return netip.AddrPortFrom(ip, port)
}

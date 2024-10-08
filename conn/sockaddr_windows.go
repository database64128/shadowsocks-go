package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/windows"
)

const (
	SizeofSockaddrInet4 = uint32(unsafe.Sizeof(windows.RawSockaddrInet4{}))
	SizeofSockaddrInet6 = uint32(unsafe.Sizeof(windows.RawSockaddrInet6{}))
)

func AddrPortToSockaddrValue(addrPort netip.AddrPort) (rsa6 windows.RawSockaddrInet6, namelen uint32) {
	addr, port := addrPort.Addr(), addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	if addr.Is4() {
		rsa6.Family = windows.AF_INET
		a := (*[4]byte)(unsafe.Pointer(&rsa6.Flowinfo))
		*a = addr.As4()
		namelen = SizeofSockaddrInet4
		return
	}
	rsa6.Family = windows.AF_INET6
	rsa6.Addr = addr.As16()
	rsa6.Scope_id = uint32(netx.ZoneCache.Index(addr.Zone()))
	namelen = SizeofSockaddrInet6
	return
}

func SockaddrValueToAddrPort(rsa6 windows.RawSockaddrInet6, namelen uint32) (netip.AddrPort, error) {
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	port := uint16(p[0])<<8 + uint16(p[1])
	var addr netip.Addr
	switch namelen {
	case SizeofSockaddrInet4:
		addr = netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&rsa6.Flowinfo)))
	case SizeofSockaddrInet6:
		addr = netip.AddrFrom16(rsa6.Addr).WithZone(netx.ZoneCache.Name(int(rsa6.Scope_id)))
	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
	return netip.AddrPortFrom(addr, port), nil
}

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	if addrPort.Addr().Is4() {
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa4))
		namelen = SizeofSockaddrInet4
	} else {
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa6))
		namelen = SizeofSockaddrInet6
	}
	return
}

func AddrPortUnmappedToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	if addr := addrPort.Addr(); addr.Is4() || addr.Is4In6() {
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa4))
		namelen = SizeofSockaddrInet4
	} else {
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa6))
		namelen = SizeofSockaddrInet6
	}
	return
}

func AddrPortToSockaddrInet4(addrPort netip.AddrPort) windows.RawSockaddrInet4 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa4 := windows.RawSockaddrInet4{
		Family: windows.AF_INET,
		Addr:   addr.As4(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa4
}

func AddrPortToSockaddrInet6(addrPort netip.AddrPort) windows.RawSockaddrInet6 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa6 := windows.RawSockaddrInet6{
		Family:   windows.AF_INET6,
		Addr:     addr.As16(),
		Scope_id: uint32(netx.ZoneCache.Index(addr.Zone())),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
	case SizeofSockaddrInet4:
		rsa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(name))
		return SockaddrInet4ToAddrPort(rsa4), nil

	case SizeofSockaddrInet6:
		rsa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(name))
		return SockaddrInet6ToAddrPort(rsa6), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
}

func SockaddrInet4ToAddrPort(sa *windows.RawSockaddrInet4) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom4(sa.Addr)
	return netip.AddrPortFrom(ip, port)
}

func SockaddrInet6ToAddrPort(sa *windows.RawSockaddrInet6) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom16(sa.Addr).WithZone(netx.ZoneCache.Name(int(sa.Scope_id)))
	return netip.AddrPortFrom(ip, port)
}

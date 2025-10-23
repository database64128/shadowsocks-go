package conn

import (
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func GetRedirectOriginalDst(rawConn syscall.RawConn, is4 bool) (addrPort netip.AddrPort, err error) {
	if cerr := rawConn.Control(func(fd uintptr) {
		addrPort, err = getRedirectOriginalDst(int(fd), is4)
	}); cerr != nil {
		return netip.AddrPort{}, cerr
	}
	return addrPort, err
}

func getRedirectOriginalDst(fd int, is4 bool) (netip.AddrPort, error) {
	if is4 {
		return getRedirectOriginalDst4(fd)
	}
	return getRedirectOriginalDst6(fd)
}

func getRedirectOriginalDst4(fd int) (netip.AddrPort, error) {
	var (
		sa    unix.RawSockaddrInet4
		saLen uint32 = unix.SizeofSockaddrInet4
	)
	if errno := getsockopt(fd, unix.IPPROTO_IP, unix.SO_ORIGINAL_DST, unsafe.Pointer(&sa), &saLen); errno != 0 {
		return netip.AddrPort{}, os.NewSyscallError("getsockopt(IPPROTO_IP, SO_ORIGINAL_DST)", errno)
	}
	if saLen != unix.SizeofSockaddrInet4 {
		return netip.AddrPort{}, fmt.Errorf("getsockopt(IPPROTO_IP, SO_ORIGINAL_DST) returned unexpected sockaddr length: %d", saLen)
	}
	return SockaddrInet4ToAddrPort(&sa), nil
}

func getRedirectOriginalDst6(fd int) (netip.AddrPort, error) {
	var (
		sa    unix.RawSockaddrInet6
		saLen uint32 = unix.SizeofSockaddrInet6
	)
	// IP6T_SO_ORIGINAL_DST == SO_ORIGINAL_DST
	if errno := getsockopt(fd, unix.IPPROTO_IPV6, unix.SO_ORIGINAL_DST, unsafe.Pointer(&sa), &saLen); errno != 0 {
		return netip.AddrPort{}, os.NewSyscallError("getsockopt(IPPROTO_IPV6, SO_ORIGINAL_DST)", errno)
	}
	if saLen != unix.SizeofSockaddrInet6 {
		return netip.AddrPort{}, fmt.Errorf("getsockopt(IPPROTO_IPV6, SO_ORIGINAL_DST) returned unexpected sockaddr length: %d", saLen)
	}
	return SockaddrInet6ToAddrPort(&sa), nil
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *uint32) syscall.Errno {
	_, _, e1 := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	return e1
}

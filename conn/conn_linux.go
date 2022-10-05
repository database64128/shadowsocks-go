package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/database64128/tfo-go/v2"
	"golang.org/x/sys/unix"
)

const (
	// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
	SocketControlMessageBufferSize = unix.SizeofCmsghdr + (unix.SizeofInet6Pktinfo+unix.SizeofPtr-1) & ^(unix.SizeofPtr-1)

	// TransparentSocketControlMessageBufferSize specifies the buffer size for receiving IPV6_RECVORIGDSTADDR socket control messages.
	TransparentSocketControlMessageBufferSize = unix.SizeofCmsghdr + (unix.SizeofSockaddrInet6+unix.SizeofPtr-1) & ^(unix.SizeofPtr-1)
)

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func setTransparent(fd int, network string) error {
	switch network {
	case "tcp4", "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_TRANSPARENT: %w", err)
		}
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_TRANSPARENT: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

func setDF(fd int, network string) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
	}

	if network == "udp6" {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	}

	return nil
}

func setPktinfo(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

func setRecvOrigDstAddr(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_RECVORIGDSTADDR: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVORIGDSTADDR: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

// NewDialer returns a tfo.Dialer with the specified options applied.
func NewDialer(dialerTFO bool, dialerFwmark int) (dialer tfo.Dialer) {
	dialer.DisableTFO = !dialerTFO
	if dialerFwmark != 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) (err error) {
			if cerr := c.Control(func(fd uintptr) {
				err = setFwmark(int(fd), dialerFwmark)
			}); cerr != nil {
				return cerr
			}
			return
		}
	}
	return
}

// NewListenConfig returns a tfo.ListenConfig with the specified options applied.
func NewListenConfig(listenerTFO, listenerTransparent bool, listenerFwmark int) (lc tfo.ListenConfig) {
	lc.DisableTFO = !listenerTFO
	if listenerTransparent || listenerFwmark != 0 {
		lc.Control = func(network, address string, c syscall.RawConn) (err error) {
			if cerr := c.Control(func(fd uintptr) {
				if listenerTransparent {
					if err = setTransparent(int(fd), network); err != nil {
						return
					}
				}
				if listenerFwmark != 0 {
					err = setFwmark(int(fd), listenerFwmark)
				}
			}); cerr != nil {
				return cerr
			}
			return
		}
	}
	return
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and sets socket options on supported platforms.
//
// On Linux and Windows, IP_MTU_DISCOVER and IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO to disable IP fragmentation
// and encourage correct MTU settings. If pktinfo is true, IP_PKTINFO and IPV6_RECVPKTINFO are set to 1.
//
// On Linux, SO_MARK is set to user-specified value.
//
// On macOS and FreeBSD, IP_DONTFRAG, IPV6_DONTFRAG are set to 1 (Don't Fragment).
func ListenUDP(network string, laddr string, pktinfo bool, fwmark int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			if cerr := c.Control(func(fd uintptr) {
				if err = setDF(int(fd), network); err != nil {
					return
				}

				if pktinfo {
					if err = setPktinfo(int(fd), network); err != nil {
						return
					}
				}

				if fwmark != 0 {
					err = setFwmark(int(fd), fwmark)
				}
			}); cerr != nil {
				return cerr
			}
			return
		},
	}

	pc, err := lc.ListenPacket(context.Background(), network, laddr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func ListenUDPTransparent(network string, laddr string, fwmark int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			if cerr := c.Control(func(fd uintptr) {
				if err = setTransparent(int(fd), network); err != nil {
					return
				}

				if err = setRecvOrigDstAddr(int(fd), network); err != nil {
					return
				}

				if fwmark != 0 {
					err = setFwmark(int(fd), fwmark)
				}
			}); cerr != nil {
				return cerr
			}
			return
		},
	}

	pc, err := lc.ListenPacket(context.Background(), network, laddr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ParsePktinfoCmsg parses a single socket control message of type IP_PKTINFO or IPV6_PKTINFO,
// and returns the IP address and index of the network interface the packet was received from,
// or an error.
//
// This function is only implemented for Linux and Windows. On other platforms, this is a no-op.
func ParsePktinfoCmsg(cmsg []byte) (netip.Addr, uint32, error) {
	if len(cmsg) < unix.SizeofCmsghdr {
		return netip.Addr{}, 0, fmt.Errorf("control message length %d is shorter than cmsghdr length", len(cmsg))
	}

	cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsg[0]))

	switch {
	case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_PKTINFO && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo:
		pktinfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return netip.AddrFrom4(pktinfo.Spec_dst), uint32(pktinfo.Ifindex), nil

	case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo:
		pktinfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return netip.AddrFrom16(pktinfo.Addr), pktinfo.Ifindex, nil

	default:
		return netip.Addr{}, 0, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}
}

func ParseOrigDstAddrCmsg(cmsg []byte) (netip.AddrPort, error) {
	if len(cmsg) < unix.SizeofCmsghdr {
		return netip.AddrPort{}, fmt.Errorf("control message length %d is shorter than cmsghdr length", len(cmsg))
	}

	cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsg[0]))

	switch {
	case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_ORIGDSTADDR && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofSockaddrInet4:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return SockaddrInet4ToAddrPort(sa), nil

	case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_ORIGDSTADDR && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofSockaddrInet6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return SockaddrInet6ToAddrPort(sa), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}
}

// Source: include/uapi/linux/uio.h
const UIO_MAXIOV = 1024

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

func AddrPortToSockaddrValue(addrPort netip.AddrPort) (rsa6 unix.RawSockaddrInet6, namelen uint32) {
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
	namelen = unix.SizeofSockaddrInet6
	return
}

func SockaddrValueToAddrPort(rsa6 unix.RawSockaddrInet6, namelen uint32) (netip.AddrPort, error) {
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	port := uint16(p[0])<<8 + uint16(p[1])
	var addr netip.Addr
	switch namelen {
	case unix.SizeofSockaddrInet4:
		addr = netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&rsa6.Flowinfo)))
	case unix.SizeofSockaddrInet6:
		addr = netip.AddrFrom16(rsa6.Addr)
	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
	return netip.AddrPortFrom(addr, port), nil
}

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	if addrPort.Addr().Is4() {
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa4))
		namelen = unix.SizeofSockaddrInet4
	} else {
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa6))
		namelen = unix.SizeofSockaddrInet6
	}

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
		Family: unix.AF_INET6,
		Addr:   addr.As16(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
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
	ip := netip.AddrFrom16(sa.Addr)
	return netip.AddrPortFrom(ip, port)
}

func Recvmmsg(conn *net.UDPConn, msgvec []Mmsghdr) (n int, err error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	perr := rawConn.Read(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&msgvec[0])), uintptr(len(msgvec)), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("recvmmsg failed: %w", e1)
			return true
		}
		n = int(r0)
		return true
	})

	if err == nil {
		err = perr
	}

	return
}

func Sendmmsg(conn *net.UDPConn, msgvec []Mmsghdr) (n int, err error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	perr := rawConn.Write(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&msgvec[0])), uintptr(len(msgvec)), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("sendmmsg failed: %w", e1)
			return true
		}
		n = int(r0)
		return true
	})

	if err == nil {
		err = perr
	}

	return
}

// WriteMsgvec repeatedly calls sendmmsg(2) until all messages in msgvec are written to the socket.
//
// If the syscall returns an error, this function drops the message that caused the error,
// and continues sending. Only the last encountered error is returned.
func WriteMsgvec(conn *net.UDPConn, msgvec []Mmsghdr) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	var processed int

	perr := rawConn.Write(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&msgvec[processed])), uintptr(len(msgvec)-processed), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("sendmmsg failed: %w", e1)
			r0 = 1
		}
		processed += int(r0)
		return processed >= len(msgvec)
	})

	if err == nil {
		err = perr
	}

	return err
}

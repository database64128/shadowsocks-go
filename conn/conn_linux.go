package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TransparentSocketControlMessageBufferSize specifies the buffer size for receiving IPV6_RECVORIGDSTADDR socket control messages.
const TransparentSocketControlMessageBufferSize = unix.SizeofCmsghdr + (unix.SizeofSockaddrInet6+unix.SizeofPtr-1) & ^(unix.SizeofPtr-1)

func setSendBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
	return nil
}

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func setTrafficClass(fd int, network string, trafficClass int) error {
	// Set IP_TOS for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, trafficClass); err != nil {
		return fmt.Errorf("failed to set socket option IP_TOS: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_TCLASS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setTCPDeferAccept(fd, secs int) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, secs); err != nil {
		return fmt.Errorf("failed to set socket option TCP_DEFER_ACCEPT: %w", err)
	}
	return nil
}

func setTCPUserTimeout(fd, msecs int) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, msecs); err != nil {
		return fmt.Errorf("failed to set socket option TCP_USER_TIMEOUT: %w", err)
	}
	return nil
}

func probeUDPGSOSupport(fd int, info *SocketInfo) {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0); err == nil {
		// UDP_MAX_SEGMENTS as defined in linux/udp.h was originally 64.
		// It got bumped to 128 in Linux 6.9: https://github.com/torvalds/linux/commit/1382e3b6a3500c245e5278c66d210c02926f804f
		// The receive path still only supports 64 segments, so 64 it is.
		info.MaxUDPGSOSegments = 64
	}
}

func setUDPGenericReceiveOffload(fd int, info *SocketInfo) {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err == nil {
		info.UDPGenericReceiveOffload = true
	}
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

func setPMTUD(fd int, network string) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setRecvPktinfo(fd int, network string) error {
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
	// Set IP_RECVORIGDSTADDR for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
		return fmt.Errorf("failed to set socket option IP_RECVORIGDSTADDR: %w", err)
	}

	switch network {
	case "udp4":
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVORIGDSTADDR: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func (fns setFuncSlice) appendSetTCPDeferAcceptFunc(deferAcceptSecs int) setFuncSlice {
	if deferAcceptSecs > 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setTCPDeferAccept(fd, deferAcceptSecs)
		})
	}
	return fns
}

func (fns setFuncSlice) appendSetTCPUserTimeoutFunc(userTimeoutMsecs int) setFuncSlice {
	if userTimeoutMsecs > 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setTCPUserTimeout(fd, userTimeoutMsecs)
		})
	}
	return fns
}

func (fns setFuncSlice) appendSetTransparentFunc(transparent bool) setFuncSlice {
	if transparent {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setTransparent(fd, network)
		})
	}
	return fns
}

func (fns setFuncSlice) appendSetRecvOrigDstAddrFunc(recvOrigDstAddr bool) setFuncSlice {
	if recvOrigDstAddr {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setRecvOrigDstAddr(fd, network)
		})
	}
	return fns
}

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetFwmarkFunc(lso.Fwmark).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetTCPDeferAcceptFunc(lso.TCPDeferAcceptSecs).
		appendSetTCPUserTimeoutFunc(lso.TCPUserTimeoutMsecs).
		appendSetReusePortFunc(lso.ReusePort).
		appendSetTransparentFunc(lso.Transparent).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendProbeUDPGSOSupportFunc(lso.ProbeUDPGSOSupport).
		appendSetUDPGenericReceiveOffloadFunc(lso.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo).
		appendSetRecvOrigDstAddrFunc(lso.ReceiveOriginalDestAddr)
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

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setSendBufferSize(fd, size int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
	return nil
}

func setRecvBufferSize(fd, size int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
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

func setIPv6SourceAddressPreference(fd int, network string, pref IPv6SourceAddressPreference) error {
	switch network {
	case "tcp6", "udp6":
	default:
		return nil
	}

	// Currently these constants are only defined in /usr/include/linux/in6.h,
	// which x/sys/unix does not include. It's not clear if we are allowed to
	// add #include <linux/in6.h> to x/sys/unix. The existing includes seem to
	// prefer glibc header files.
	const (
		IPV6_PREFER_SRC_TMP            = 0x1
		IPV6_PREFER_SRC_PUBLIC         = 0x2
		IPV6_PREFER_SRC_COA            = 0x4
		IPV6_PREFER_SRC_CGA            = 0x8
		IPV6_PREFER_SRC_PUBTMP_DEFAULT = 0x100
		IPV6_PREFER_SRC_HOME           = 0x400
		IPV6_PREFER_SRC_NONCGA         = 0x800
	)

	var value int
	for i := ipv6SourceAddressPreferenceMin; i <= ipv6SourceAddressPreferenceMax; i <<= 1 {
		if pref&i != 0 {
			switch i {
			case IPv6SourceAddressPreferencePreferHome:
				value |= IPV6_PREFER_SRC_HOME
			case IPv6SourceAddressPreferencePreferCOA:
				value |= IPV6_PREFER_SRC_COA
			case IPv6SourceAddressPreferencePreferTemporary:
				value |= IPV6_PREFER_SRC_TMP
			case IPv6SourceAddressPreferencePreferPublic:
				value |= IPV6_PREFER_SRC_PUBLIC
			case IPv6SourceAddressPreferencePreferCGA:
				value |= IPV6_PREFER_SRC_CGA
			case IPv6SourceAddressPreferencePreferNonCGA:
				value |= IPV6_PREFER_SRC_NONCGA
			}
		}
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_ADDR_PREFERENCES, value); err != nil {
		return fmt.Errorf("failed to set socket option IPV6_ADDR_PREFERENCES to %#x: %w", value, err)
	}
	return nil
}

func setBindAddressNoPort(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 1); err != nil {
		return fmt.Errorf("failed to set socket option IP_BIND_ADDRESS_NO_PORT: %w", err)
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
		if info != nil {
			info.MaxUDPGSOSegments = 64
		}
	}
}

func setUDPGenericReceiveOffload(fd int, info *SocketInfo) {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err == nil {
		if info != nil {
			info.UDPGenericReceiveOffload = true
		}
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

func (fns setFuncSlice) appendSetPMTUDFunc(pmtud PMTUDMode) setFuncSlice {
	var value int
	switch pmtud {
	case PMTUDModeDont:
		value = unix.IP_PMTUDISC_DONT
	case PMTUDModeDo:
		value = unix.IP_PMTUDISC_DO
	case PMTUDModeProbe:
		value = unix.IP_PMTUDISC_PROBE
	case PMTUDModeWant:
		value = unix.IP_PMTUDISC_WANT
	case PMTUDModeInterface:
		value = unix.IP_PMTUDISC_INTERFACE
	case PMTUDModeOmit:
		value = unix.IP_PMTUDISC_OMIT
	default:
		return fns
	}
	return append(fns, func(fd int, network string, _ *SocketInfo) error {
		return setPMTUD(fd, network, value)
	})
}

func setPMTUD(fd int, network string, value int) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, value); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER to %d: %w", value, err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, value); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER to %d: %w", value, err)
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

func (fns setFuncSlice) appendSetBindAddressNoPortFunc(bindAddressNoPort bool) setFuncSlice {
	if bindAddressNoPort {
		return append(fns, func(fd int, _ string, _ *SocketInfo) error {
			return setBindAddressNoPort(fd)
		})
	}
	return fns
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

func (opts TCPListenSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetFwmarkFunc(opts.Fwmark).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetTCPDeferAcceptFunc(opts.TCPDeferAcceptSecs).
		appendSetTCPUserTimeoutFunc(opts.TCPUserTimeoutMsecs).
		appendSetReusePortFunc(opts.ReusePort).
		appendSetTransparentFunc(opts.Transparent).
		appendSetPMTUDFunc(opts.PathMTUDiscovery)
}

func (opts TCPConnectSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetFwmarkFunc(opts.Fwmark).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetIPv6SourceAddressPreference(opts.IPv6SourceAddressPreference).
		appendSetTCPUserTimeoutFunc(opts.TCPUserTimeoutMsecs).
		appendSetBindAddressNoPortFunc(opts.BindAddressNoPort).
		appendSetPMTUDFunc(opts.PathMTUDiscovery)
}

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetFwmarkFunc(opts.Fwmark).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetIPv6SourceAddressPreference(opts.IPv6SourceAddressPreference).
		appendSetReusePortFunc(opts.ReusePort).
		appendSetTransparentFunc(opts.Transparent).
		appendSetPMTUDFunc(opts.PathMTUDiscovery).
		appendProbeUDPGSOSupportFunc(opts.ProbeUDPGSOSupport).
		appendSetUDPGenericReceiveOffloadFunc(opts.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo).
		appendSetRecvOrigDstAddrFunc(opts.ReceiveOriginalDestAddr)
}

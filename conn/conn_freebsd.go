package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_USER_COOKIE, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func setTransparent(fd int, network string) error {
	switch network {
	case "tcp4", "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BINDANY, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_BINDANY: %w", err)
		}
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BINDANY, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_BINDANY: %w", err)
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

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetFwmarkFunc(lso.Fwmark).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetReusePortFunc(lso.ReusePort).
		appendSetTransparentFunc(lso.Transparent).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo).
		appendSetRecvOrigDstAddrFunc(lso.ReceiveOriginalDestAddr)
}

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setTransparent(fd int, _ string) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDANY, 1); err != nil {
		return fmt.Errorf("failed to set socket option SO_BINDANY: %w", err)
	}
	return nil
}

func setRecvOrigDstAddr(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_RECVDSTADDR: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVDSTPORT, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_RECVDSTPORT: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVDSTPORT, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVDSTPORT: %w", err)
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
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetReusePortFunc(lso.ReusePort).
		appendSetTransparentFunc(lso.Transparent).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo).
		appendSetRecvOrigDstAddrFunc(lso.ReceiveOriginalDestAddr)
}

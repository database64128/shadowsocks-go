//go:build darwin || freebsd

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func (fns setFuncSlice) appendSetPMTUDFunc(pmtud PMTUDMode) setFuncSlice {
	var value int
	switch pmtud {
	case PMTUDModeDont:
		value = 0
	case PMTUDModeDo:
		value = 1
	default:
		return fns
	}
	return append(fns, func(fd int, network string, _ *SocketInfo) error {
		return setPMTUD(fd, network, value)
	})
}

func setPMTUD(fd int, network string, value int) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, value); err != nil {
			return fmt.Errorf("failed to set socket option IP_DONTFRAG to %d: %w", value, err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, value); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_DONTFRAG to %d: %w", value, err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

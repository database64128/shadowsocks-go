//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || zos

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setReusePort(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("failed to set socket option SO_REUSEPORT: %w", err)
	}
	return nil
}

func (fns setFuncSlice) appendSetReusePortFunc(reusePort bool) setFuncSlice {
	if reusePort {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setReusePort(fd)
		})
	}
	return fns
}

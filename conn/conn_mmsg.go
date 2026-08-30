//go:build linux || netbsd

package conn

import (
	"context"
)

// ListenUDPMmsgConn is like [UDPSocketConfig.Listen] but wraps the [*net.UDPConn] in a [MmsgConn]
// for reading and writing multiple messages using the recvmmsg(2) and sendmmsg(2) system calls.
func ListenUDPMmsgConn(ctx context.Context, network, address string, info *SocketInfo, cfg UDPSocketConfig) (MmsgConn, error) {
	uc, err := cfg.Listen(ctx, network, address, info)
	if err != nil {
		return MmsgConn{}, err
	}

	mc, err := NewMmsgConn(uc)
	if err != nil {
		_ = uc.Close()
		return MmsgConn{}, err
	}

	return mc, nil
}

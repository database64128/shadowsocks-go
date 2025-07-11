//go:build darwin || freebsd || linux || openbsd || windows

package conn

func (fns setFuncSlice) appendSetRecvPktinfoFunc(recvPktinfo bool) setFuncSlice {
	if recvPktinfo {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setRecvPktinfo(fd, network)
		})
	}
	return fns
}

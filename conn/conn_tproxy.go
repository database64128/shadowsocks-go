//go:build freebsd || linux || openbsd

package conn

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

//go:build freebsd || linux

package conn

func (fns setFuncSlice) appendSetFwmarkFunc(fwmark int) setFuncSlice {
	if fwmark != 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setFwmark(fd, fwmark)
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

func (dso DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetFwmarkFunc(dso.Fwmark).
		appendSetTrafficClassFunc(dso.TrafficClass)
}

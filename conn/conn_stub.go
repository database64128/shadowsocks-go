//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package conn

func (TCPListenSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

func (TCPConnectSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

func (UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

func (UnixDomainSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

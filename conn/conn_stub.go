//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package conn

func (ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

func (DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

func (UnixDomainSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

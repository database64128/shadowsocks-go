//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos

package conn

func (dso DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

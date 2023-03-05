//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows && !zos

package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

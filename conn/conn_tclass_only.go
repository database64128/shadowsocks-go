//go:build aix || darwin || dragonfly || netbsd || openbsd || solaris || zos

package conn

func (dso DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.appendSetTrafficClassFunc(dso.TrafficClass)
}

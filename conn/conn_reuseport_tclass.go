//go:build aix || dragonfly || netbsd || openbsd || zos

package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetReusePortFunc(lso.ReusePort)
}

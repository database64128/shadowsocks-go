//go:build aix || dragonfly || netbsd || openbsd || solaris || zos

package conn

func (dso DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(dso.SendBufferSize).
		appendSetRecvBufferSize(dso.ReceiveBufferSize).
		appendSetTrafficClassFunc(dso.TrafficClass)
}

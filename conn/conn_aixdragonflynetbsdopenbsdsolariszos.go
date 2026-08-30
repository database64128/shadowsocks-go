//go:build aix || dragonfly || netbsd || openbsd || solaris || zos

package conn

func (opts TCPConnectSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass)
}

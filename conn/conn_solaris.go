package conn

func (opts TCPListenSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass)
}

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

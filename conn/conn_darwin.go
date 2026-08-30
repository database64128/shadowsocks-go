package conn

func (opts TCPListenSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetReusePortFunc(opts.ReusePort).
		appendSetPMTUDFunc(opts.PathMTUDiscovery)
}

func (opts TCPConnectSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetPMTUDFunc(opts.PathMTUDiscovery)
}

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetReusePortFunc(opts.ReusePort).
		appendSetPMTUDFunc(opts.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

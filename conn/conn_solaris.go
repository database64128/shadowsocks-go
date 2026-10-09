package conn

const defaultUDPSocketBufferSize = 0

func (opts TCPListenSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass)
}

func (opts TCPConnectSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetIPv6SourceAddressPreference(opts.IPv6SourceAddressPreference)
}

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetIPv6SourceAddressPreference(opts.IPv6SourceAddressPreference).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetReusePortFunc(lso.ReusePort).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}

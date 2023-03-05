package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.appendSetTrafficClassFunc(lso.TrafficClass)
}

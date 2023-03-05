package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetReusePortFunc(lso.ReusePort).
		appendSetPMTUDFunc(lso.PathMTUDiscovery)
}

//go:build darwin || dragonfly || freebsd || linux || solaris || zos

package conn

func (fns setFuncSlice) appendSetIPv6SourceAddressPreference(pref IPv6SourceAddressPreference) setFuncSlice {
	if pref != 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setIPv6SourceAddressPreference(fd, network, pref)
		})
	}
	return fns
}

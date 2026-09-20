package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setIPv6SourceAddressPreference(fd int, network string, pref IPv6SourceAddressPreference) error {
	switch network {
	case "tcp6", "udp6":
	default:
		return nil
	}

	var value int
	for i := ipv6SourceAddressPreferenceMin; i <= ipv6SourceAddressPreferenceMax; i <<= 1 {
		if pref&i != 0 {
			switch i {
			case IPv6SourceAddressPreferencePreferHome:
				value |= unix.IPV6_PREFER_SRC_HOME
			case IPv6SourceAddressPreferencePreferCOA:
				value |= unix.IPV6_PREFER_SRC_COA
			case IPv6SourceAddressPreferencePreferTemporary:
				value |= unix.IPV6_PREFER_SRC_TMP
			case IPv6SourceAddressPreferencePreferPublic:
				value |= unix.IPV6_PREFER_SRC_PUBLIC
			case IPv6SourceAddressPreferencePreferCGA:
				value |= unix.IPV6_PREFER_SRC_CGA
			case IPv6SourceAddressPreferencePreferNonCGA:
				value |= unix.IPV6_PREFER_SRC_NONCGA
			}
		}
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_ADDR_PREFERENCES, value); err != nil {
		return fmt.Errorf("failed to set socket option IPV6_ADDR_PREFERENCES to %#x: %w", value, err)
	}
	return nil
}

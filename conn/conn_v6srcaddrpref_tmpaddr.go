//go:build darwin || dragonfly || freebsd

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

	//  - https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/ip6_var.h
	//  - https://github.com/DragonFlyBSD/DragonFlyBSD/blob/master/sys/netinet6/ip6_var.h
	//  - https://github.com/freebsd/freebsd-src/blob/main/sys/netinet6/ip6_var.h
	//
	// These share the same definitions:
	//
	//	#define IP6PO_TEMPADDR_SYSTEM	-1 /* follow the system default */
	//	#define IP6PO_TEMPADDR_NOTPREFER 0 /* not prefer temporary address */
	//	#define IP6PO_TEMPADDR_PREFER	 1 /* prefer temporary address */
	const (
		IP6PO_TEMPADDR_SYSTEM    = -1
		IP6PO_TEMPADDR_NOTPREFER = 0
		IP6PO_TEMPADDR_PREFER    = 1
	)

	var value int
	if pref&IPv6SourceAddressPreferencePreferTemporary != 0 {
		value = IP6PO_TEMPADDR_PREFER
	}
	if pref&IPv6SourceAddressPreferencePreferPublic != 0 {
		value = IP6PO_TEMPADDR_NOTPREFER
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_PREFER_TEMPADDR, value); err != nil {
		return fmt.Errorf("failed to set socket option IPV6_PREFER_TEMPADDR to %#x: %w", value, err)
	}
	return nil
}

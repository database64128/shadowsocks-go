package ss2022

import (
	"fmt"

	"github.com/database64128/shadowsocks-go/conn"
)

// PaddingPolicy is a function that takes the target address and
// returns whether padding should be added.
type PaddingPolicy func(targetAddr conn.Addr) (shouldPad bool)

// NoPadding is a PaddingPolicy that never adds padding.
func NoPadding(_ conn.Addr) bool {
	return false
}

// PadAll is a PaddingPolicy that adds padding to all traffic.
func PadAll(_ conn.Addr) bool {
	return true
}

// PadPlainDNS is a PaddingPolicy that adds padding to plain DNS traffic.
func PadPlainDNS(targetAddr conn.Addr) bool {
	return targetAddr.Port() == 53
}

// ParsePaddingPolicy parses a string representation of a PaddingPolicy.
func ParsePaddingPolicy(paddingPolicy string) (PaddingPolicy, error) {
	switch paddingPolicy {
	case "NoPadding":
		return NoPadding, nil
	case "PadAll":
		return PadAll, nil
	case "PadPlainDNS", "":
		return PadPlainDNS, nil
	default:
		return nil, fmt.Errorf("invalid padding policy: %s", paddingPolicy)
	}
}

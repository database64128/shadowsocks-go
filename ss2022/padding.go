package ss2022

import "github.com/database64128/shadowsocks-go/socks5"

// PaddingPolicy is a function that takes the target address and
// returns whether padding should be added.
type PaddingPolicy func(targetAddr socks5.Addr) (shouldPad bool)

// NoPadding is a PaddingPolicy that never adds padding.
func NoPadding(_ socks5.Addr) bool {
	return false
}

// PadAll is a PaddingPolicy that adds padding to all traffic.
func PadAll(_ socks5.Addr) bool {
	return true
}

// PadPlainDNS is a PaddingPolicy that adds padding to plain DNS traffic.
func PadPlainDNS(targetAddr socks5.Addr) bool {
	return targetAddr.Port() == 53
}

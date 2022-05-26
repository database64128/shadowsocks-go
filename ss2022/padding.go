package ss2022

import "github.com/database64128/shadowsocks-go/socks5"

func NoPadding(_ socks5.Addr) bool {
	return false
}

func PadAll(_ socks5.Addr) bool {
	return true
}

func PadPlainDNS(targetAddr socks5.Addr) bool {
	return targetAddr.Port() == 53
}

// Package conntest provides test helpers for [conn].
package conntest

import "github.com/database64128/shadowsocks-go/conn"

var (
	defaultTCPListenConfig        = conn.DefaultTCPListenSocketOptions().Build()
	defaultTCPDialer              = conn.DefaultTCPConnectSocketOptions().Build()
	defaultUDPServerSocketConfig  = conn.DefaultUDPServerSocketOptions().Build()
	defaultUDPClientSocketConfig  = conn.DefaultUDPClientSocketOptions().Build()
	defaultUnixDomainSocketConfig = conn.DefaultUnixDomainSocketOptions().Build()
)

// DefaultTCPListenConfig returns the default [conn.TCPListenConfig] for TCP servers.
func DefaultTCPListenConfig() conn.TCPListenConfig {
	return defaultTCPListenConfig
}

// DefaultTCPDialer returns the default [conn.TCPDialer] for TCP clients.
func DefaultTCPDialer() conn.TCPDialer {
	return defaultTCPDialer
}

// DefaultUDPServerSocketConfig returns the default [conn.UDPSocketConfig] for UDP servers.
func DefaultUDPServerSocketConfig() conn.UDPSocketConfig {
	return defaultUDPServerSocketConfig
}

// DefaultUDPClientSocketConfig returns the default [conn.UDPSocketConfig] for UDP clients.
func DefaultUDPClientSocketConfig() conn.UDPSocketConfig {
	return defaultUDPClientSocketConfig
}

// DefaultUnixDomainSocketConfig returns the default [conn.UnixDomainSocketConfig].
func DefaultUnixDomainSocketConfig() conn.UnixDomainSocketConfig {
	return defaultUnixDomainSocketConfig
}

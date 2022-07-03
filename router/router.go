package router

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// Router looks up the destination client for requests received by servers.
type Router interface {
	// GetTCPClient returns the zerocopy.TCPClient for a TCP request received by serverName
	// from sourceAddr to targetAddr.
	GetTCPClient(serverName string, sourceAddr, targetAddr socks5.Addr) (zerocopy.TCPClient, error)

	// GetUDPClient returns the zerocopy.UDPClient for a UDP session received by serverName.
	// The first received packet of the session is from sourceAddr to targetAddr.
	GetUDPClient(serverName string, sourceAddr, targetAddr socks5.Addr) (zerocopy.UDPClient, error)
}

type RouteConfig struct {
	ServerNames []string       `json:"serverNames"`
	Domains     []string       `json:"domains"`
	Prefixes    []netip.Prefix `json:"prefixes"`
	Ports       []int          `json:"ports"`
	Network     string         `json:"networks"`
	ClientName  string         `json:"clientName"`
}

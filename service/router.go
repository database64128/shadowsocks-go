package service

import (
	"net/netip"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

type Router interface {
	GetTCPClient(name string, targetAddr socks5.Addr) zerocopy.TCPClient
	GetUDPClient(name string, initialTargetAddr socks5.Addr) zerocopy.UDPClient
}

type RouteConfig struct {
	ServerNames []string       `json:"serverNames"`
	Networks    []string       `json:"networks"`
	Domains     []string       `json:"domains"`
	Prefixes    []netip.Prefix `json:"prefixes"`
	ClientName  string         `json:"clientName"`
}

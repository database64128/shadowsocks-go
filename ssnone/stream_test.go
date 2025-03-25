package ssnone_test

import (
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"github.com/database64128/shadowsocks-go/ssnone"
)

func TestStreamClientServer(t *testing.T) {
	addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 8388)

	newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
		clientConfig := ssnone.StreamClientConfig{
			Name:        "test",
			InnerClient: psc,
			Addr:        addr,
		}
		return clientConfig.NewStreamClient()
	}

	netiotest.TestPreambleStreamClientServerProceed(t, newClient, ssnone.StreamServer{}, addr, "")
}

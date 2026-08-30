package conn_test

import (
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/conntest"
)

func TestListenUDP(t *testing.T) {
	for _, scc := range []struct {
		name string
		sc   conn.UDPSocketConfig
	}{
		{"DefaultUDPServerSocketConfig", conntest.DefaultUDPServerSocketConfig()},
		{"DefaultUDPClientSocketConfig", conntest.DefaultUDPClientSocketConfig()},
	} {
		t.Run(scc.name, func(t *testing.T) {
			for _, nac := range []struct {
				name    string
				network string
				address string
			}{
				{"udp+zero", "udp", ""},
				{"udp+loopback4", "udp4", "127.0.0.1:"},
				{"udp+loopback6", "udp6", "[::1]:"},
				{"udp4+zero", "udp4", ""},
				{"udp4+loopback4", "udp4", "127.0.0.1:"},
				{"udp6+zero", "udp6", ""},
				{"udp6+loopback6", "udp6", "[::1]:"},
			} {
				t.Run(nac.name, func(t *testing.T) {
					uc, err := scc.sc.Listen(t.Context(), nac.network, nac.address, nil)
					if err != nil {
						t.Fatal(err)
					}
					_ = uc.Close()
				})
			}
		})
	}
}

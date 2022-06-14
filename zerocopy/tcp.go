package zerocopy

import (
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/tfo-go"
)

type TCPClient interface {
	Dial(targetAddr socks5.Addr) (rw ReadWriter, err error)
}

type TCPServer interface {
	Accept(conn tfo.Conn) (targetAddr socks5.Addr, rw ReadWriter, err error)
}

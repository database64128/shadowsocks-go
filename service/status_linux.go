package service

import (
	"context"
	"net"
	"os"
	"strconv"
	_ "unsafe"

	"github.com/database64128/shadowsocks-go/conn"
)

// This is an implementation of sd_notify(3) for systemd.service(5).

type statusNotifier struct {
	notifyConn *net.UnixConn
}

func newStatusNotifier(ctx context.Context) statusNotifier {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" || path[0] != '/' && path[0] != '@' {
		return statusNotifier{}
	}

	var udsCfg conn.UnixDomainSocketConfig
	c, err := udsCfg.Dial(ctx, "unixgram", nil, &net.UnixAddr{
		Name: path,
		Net:  "unixgram",
	})
	if err != nil {
		return statusNotifier{}
	}
	return statusNotifier{
		notifyConn: c,
	}
}

func (sn statusNotifier) Close() error {
	if sn.notifyConn != nil {
		return sn.notifyConn.Close()
	}
	return nil
}

func (sn statusNotifier) Ready() {
	if sn.notifyConn != nil {
		sn.notifyConn.Write([]byte("READY=1"))
	}
}

func (sn statusNotifier) Stopping() {
	if sn.notifyConn != nil {
		sn.notifyConn.Write([]byte("STOPPING=1"))
	}
}

func (sn statusNotifier) Reloading() {
	if sn.notifyConn == nil {
		return
	}
	const maxMsgLen = len("RELOADING=1\nMONOTONIC_USEC=18446744073709551615")
	b := make([]byte, 0, maxMsgLen)
	b = append(b, "RELOADING=1\nMONOTONIC_USEC="...)
	b = strconv.AppendInt(b, nanotime()/1e3, 10)
	sn.notifyConn.Write(b)
}

//go:linkname nanotime runtime.nanotime
func nanotime() int64

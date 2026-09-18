//go:build !unix

package service

import (
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
)

type reloadNotifier struct{}

func newReloadNotifier(_ *tslog.Logger, _ *cred.Manager, _ *tlscerts.Store) reloadNotifier {
	return reloadNotifier{}
}

func (*reloadNotifier) start() {}
func (*reloadNotifier) stop()  {}

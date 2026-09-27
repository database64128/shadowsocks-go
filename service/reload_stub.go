//go:build !unix

package service

import (
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
)

type reloadNotifier struct{}

func (*reloadNotifier) Init(_ *tslog.Logger, _ *cred.Manager, _ *tlscerts.Store) {}
func (*reloadNotifier) Start(statusNotifier)                                     {}
func (*reloadNotifier) Stop()                                                    {}

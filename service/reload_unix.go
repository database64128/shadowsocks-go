//go:build unix

package service

import (
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"go.uber.org/zap"
)

type reloadNotifier struct {
	sigCh chan os.Signal
	fns   []func()
}

func newReloadNotifier(logger *zap.Logger, credmgr *cred.Manager, tlsCertStore *tlscerts.Store) reloadNotifier {
	rn := reloadNotifier{
		sigCh: make(chan os.Signal, 1),
	}

	if cmsCount, cmsSeq := credmgr.Servers(); cmsCount > 0 {
		cms := slices.AppendSeq(make([]*cred.ManagedServer, 0, cmsCount), cmsSeq)
		rn.fns = append(rn.fns, func() {
			for _, s := range cms {
				name := s.Name()
				if err := s.LoadFromFile(); err != nil {
					logger.Warn("Failed to reload server credentials", zap.String("server", name), zap.Error(err))
					continue
				}
				logger.Info("Reloaded server credentials", zap.String("server", name))
			}
		})
	}

	if certLists := tlsCertStore.ReloadableCertLists(); len(certLists) > 0 {
		rn.fns = append(rn.fns, func() {
			for _, certList := range certLists {
				name := certList.Config().Name
				if err := certList.Reload(); err != nil {
					logger.Warn("Failed to reload TLS certificate list", zap.String("certList", name), zap.Error(err))
					continue
				}
				logger.Info("Reloaded TLS certificate list", zap.String("certList", name))
			}
		})
	}

	return rn
}

func (rn *reloadNotifier) start() {
	if len(rn.fns) == 0 {
		return
	}
	signal.Notify(rn.sigCh, syscall.SIGUSR1)
	go func() {
		for range rn.sigCh {
			for _, fn := range rn.fns {
				fn()
			}
		}
	}()
}

func (rn *reloadNotifier) stop() {
	if len(rn.fns) == 0 {
		return
	}
	signal.Stop(rn.sigCh)
	close(rn.sigCh)
}

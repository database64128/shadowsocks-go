//go:build unix

package service

import (
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"

	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
)

type reloadNotifier struct {
	fns   []func()
	sigCh chan os.Signal
	wg    sync.WaitGroup
}

func (rn *reloadNotifier) Init(logger *tslog.Logger, credmgr *cred.Manager, tlsCertStore *tlscerts.Store) {
	if cmsCount, cmsSeq := credmgr.Servers(); cmsCount > 0 {
		cms := slices.AppendSeq(make([]*cred.ManagedServer, 0, cmsCount), cmsSeq)
		rn.fns = append(rn.fns, func() {
			for _, s := range cms {
				name := s.Name()
				if err := s.LoadFromFile(); err != nil {
					logger.Error("Failed to reload server credentials", slog.String("server", name), tslog.Err(err))
					continue
				}
				logger.Info("Reloaded server credentials", slog.String("server", name))
			}
		})
	}

	if certLists := tlsCertStore.ReloadableCertLists(); len(certLists) > 0 {
		rn.fns = append(rn.fns, func() {
			for _, certList := range certLists {
				name := certList.Config().Name
				if err := certList.Reload(); err != nil {
					logger.Error("Failed to reload TLS certificate list", slog.String("certList", name), tslog.Err(err))
					continue
				}
				logger.Info("Reloaded TLS certificate list", slog.String("certList", name))
			}
		})
	}
}

func (rn *reloadNotifier) Start(notifyStatus statusNotifier) {
	rn.sigCh = make(chan os.Signal, 1)
	signal.Notify(rn.sigCh, syscall.SIGUSR1)
	rn.wg.Go(func() {
		for range rn.sigCh {
			notifyStatus.Reloading()
			for _, fn := range rn.fns {
				fn()
			}
			notifyStatus.Ready()
		}
	})
}

// When Stop returns, no further status notifications will be sent.
func (rn *reloadNotifier) Stop() {
	signal.Stop(rn.sigCh)
	close(rn.sigCh)
	rn.wg.Wait()
}

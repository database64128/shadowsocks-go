//go:build unix

package cred

import (
	"os"
	"os/signal"
	"syscall"
)

func (m *Manager) registerSIGUSR1() {
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGUSR1)
		for range sigCh {
			m.ReloadAll()
		}
	}()
}

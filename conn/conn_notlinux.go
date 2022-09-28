//go:build !linux

package conn

import "github.com/database64128/tfo-go/v2"

// NewDialer returns a tfo.Dialer with the specified options applied.
func NewDialer(dialerTFO bool, dialerFwmark int) (dialer tfo.Dialer) {
	dialer.DisableTFO = !dialerTFO
	return
}

// NewListenConfig returns a tfo.ListenConfig with the specified options applied.
func NewListenConfig(listenerTFO bool, listenerFwmark int) (lc tfo.ListenConfig) {
	lc.DisableTFO = !listenerTFO
	return
}

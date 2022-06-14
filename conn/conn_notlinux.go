//go:build !linux

package conn

import "github.com/database64128/tfo-go"

// NewDialer returns a tfo.Dialer with the specified options applied.
func NewDialer(dialerTFO bool, dialerFwmark int) (dialer tfo.Dialer) {
	dialer.DisableTFO = !dialerTFO
	return
}

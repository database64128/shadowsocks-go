//go:build !linux

package netio

import "errors"

type tcpRedirectUnsupportedError struct{}

func (tcpRedirectUnsupportedError) Error() string {
	return "tcp redirect is not supported on this platform"
}

func (tcpRedirectUnsupportedError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

func newTCPRedirectServer() (StreamServer, error) {
	return nil, tcpRedirectUnsupportedError{}
}

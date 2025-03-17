//go:build !linux

package netio

import "errors"

type tproxyUnsupportedError struct{}

func (tproxyUnsupportedError) Error() string {
	return "tproxy is not supported on this platform"
}

func (tproxyUnsupportedError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

func newTCPTransparentProxyServer() (StreamServer, error) {
	return nil, tproxyUnsupportedError{}
}

//go:build !linux && !netbsd

package service

import "context"

func (s *UDPSessionRelay) start(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	return s.startGeneric(ctx, index, lnc)
}

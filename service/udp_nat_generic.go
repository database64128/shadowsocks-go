//go:build !linux && !netbsd

package service

func (s *UDPNATRelay) start(index int, lnc *udpRelayServerConn) error {
	return s.startGeneric(index, lnc)
}

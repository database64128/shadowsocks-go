//go:build !linux && !netbsd

package service

func (s *UDPSessionRelay) start(index int, lnc *udpRelayServerConn) error {
	return s.startGeneric(index, lnc)
}

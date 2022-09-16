//go:build !linux

package service

func (s *UDPNATRelay) setRelayFunc(batchMode string) {
	s.recvFromServerConn = s.recvFromServerConnGeneric
}

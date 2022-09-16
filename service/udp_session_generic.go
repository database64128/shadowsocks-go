//go:build !linux

package service

func (s *UDPSessionRelay) setRelayFunc(batchMode string) {
	s.recvFromServerConn = s.recvFromServerConnGeneric
}

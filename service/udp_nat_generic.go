//go:build !linux

package service

func (s *UDPNATRelay) setRecvAndRelayFunctions(batchMode string) {
	s.recvFromServerConn = s.recvFromServerConnGeneric
	s.relayServerConnToNatConn = s.relayServerConnToNatConnGeneric
	s.relayNatConnToServerConn = s.relayNatConnToServerConnGeneric
}

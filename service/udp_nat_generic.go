//go:build !linux

package service

func (s *UDPNATRelay) setRelayServerConnToNatConnFunc(batchMode string) {
	s.relayServerConnToNatConn = s.relayServerConnToNatConnGeneric
}

func (s *UDPNATRelay) setRelayNatConnToServerConnFunc(batchMode string) {
	s.relayNatConnToServerConn = s.relayNatConnToServerConnGeneric
}

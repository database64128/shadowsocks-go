//go:build !linux

package service

func (s *UDPSessionRelay) setRelayServerConnToNatConnFunc(batchMode string) {
	s.relayServerConnToNatConn = s.relayServerConnToNatConnGeneric
}

func (s *UDPSessionRelay) setRelayNatConnToServerConnFunc(batchMode string) {
	s.relayNatConnToServerConn = s.relayNatConnToServerConnGeneric
}

//go:build !linux

package service

func (s *UDPNATRelay) setStartFunc(batchMode string) {
	s.startFunc = s.startGeneric
}

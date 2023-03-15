//go:build !linux && !netbsd

package service

func (s *UDPNATRelay) setStartFunc(batchMode string) {
	s.startFunc = s.startGeneric
}

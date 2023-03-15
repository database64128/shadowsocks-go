//go:build !linux && !netbsd

package service

func (s *UDPSessionRelay) setStartFunc(batchMode string) {
	s.startFunc = s.startGeneric
}

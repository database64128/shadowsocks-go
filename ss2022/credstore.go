package ss2022

import "sync"

// CredStore stores credentials for a Shadowsocks 2022 server.
type CredStore struct {
	mu      sync.Mutex
	uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig
}

// Lock locks its internal mutex.
func (s *CredStore) Lock() {
	s.mu.Lock()
}

// Unlock unlocks its internal mutex.
func (s *CredStore) Unlock() {
	s.mu.Unlock()
}

// UpdateUPSKMap calls the given function with the current uPSKMap.
func (s *CredStore) UpdateUPSKMap(f func(uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig)) {
	s.mu.Lock()
	f(s.uPSKMap)
	s.mu.Unlock()
}

// ReplaceUPSKMap replaces the current uPSKMap with the given one.
func (s *CredStore) ReplaceUPSKMap(uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig) {
	s.mu.Lock()
	s.uPSKMap = uPSKMap
	s.mu.Unlock()
}

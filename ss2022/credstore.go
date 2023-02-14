package ss2022

import "sync"

// CredStore stores credentials for a Shadowsocks 2022 server.
type CredStore struct {
	mu  sync.Mutex
	ulm UserLookupMap
}

// Lock locks its internal mutex.
func (s *CredStore) Lock() {
	s.mu.Lock()
}

// Unlock unlocks its internal mutex.
func (s *CredStore) Unlock() {
	s.mu.Unlock()
}

// UpdateUserLookupMap calls the given function with the current user lookup map.
func (s *CredStore) UpdateUserLookupMap(f func(ulm UserLookupMap)) {
	s.mu.Lock()
	f(s.ulm)
	s.mu.Unlock()
}

// ReplaceUserLookupMap replaces the current user lookup map with the given one.
func (s *CredStore) ReplaceUserLookupMap(ulm UserLookupMap) {
	s.mu.Lock()
	s.ulm = ulm
	s.mu.Unlock()
}

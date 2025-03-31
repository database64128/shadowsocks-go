package ss2022

import "sync"

// CredStore stores credentials for a Shadowsocks 2022 server.
type CredStore struct {
	mu  sync.RWMutex
	ulm UserLookupMap
}

// LookupUser looks up the user in the user lookup map.
func (s *CredStore) LookupUser(uPSKHash [IdentityHeaderLength]byte) (ServerUserCipherConfig, bool) {
	s.mu.RLock()
	c, ok := s.ulm[uPSKHash]
	s.mu.RUnlock()
	return c, ok
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

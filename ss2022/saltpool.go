package ss2022

import (
	"sync"
	"time"
)

// SaltPool stores salts for ReplayWindowDuration to protect against replay attacks during the replay window.
// Salt type T is usually [16]byte or [32]byte.
type SaltPool[T comparable] struct {
	mu        sync.Mutex
	pool      map[T]time.Time
	retention time.Duration
}

// Add cleans the pool, checks if the salt already exists in the pool,
// and adds the salt to the pool if the salt is not already in the pool.
// Server time, instead of the header timestamp, is used, to prevent potential issues when cleaning up.
func (p *SaltPool[T]) Add(salt T) bool {
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Clean the pool.
	for salt, added := range p.pool {
		// We allow up to 30s of time diff.
		// Therefore the pool retention should be 2*30s.
		if now.Sub(added) > p.retention {
			delete(p.pool, salt)
		}
	}

	// Test existence.
	if _, ok := p.pool[salt]; ok {
		return false
	}

	// Add to pool.
	p.pool[salt] = now
	return true
}

func NewSaltPool[T comparable](retention time.Duration) *SaltPool[T] {
	return &SaltPool[T]{
		pool:      make(map[T]time.Time),
		retention: retention,
	}
}

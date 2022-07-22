package ss2022

import (
	"sync"
	"time"
)

// SaltPool stores salts for [retention, 2*retention) to protect against replay attacks during the replay window.
type SaltPool[T comparable] struct {
	mu          sync.Mutex
	pool        map[T]time.Time
	retention   time.Duration
	lastCleanup time.Time
}

// Add cleans the pool, checks if the salt already exists in the pool,
// and adds the salt to the pool if the salt is not already in the pool.
// Server time, instead of the header timestamp, is used, to prevent potential issues when cleaning up.
func (p *SaltPool[T]) Add(salt T) bool {
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Clean the pool if the amount of time since the last cleanup exceeds retention.
	if now.Sub(p.lastCleanup) > p.retention {
		for salt, added := range p.pool {
			if now.Sub(added) > p.retention {
				delete(p.pool, salt)
			}
		}
		p.lastCleanup = now
	}

	// Test existence.
	if _, ok := p.pool[salt]; ok {
		return false
	}

	// Add to pool.
	p.pool[salt] = now
	return true
}

// NewSaltPool creates a new SaltPool with retention as the minimum amount of time
// during which an added salt is guaranteed to stay in the pool.
func NewSaltPool[T comparable](retention time.Duration) *SaltPool[T] {
	return &SaltPool[T]{
		pool:        make(map[T]time.Time),
		retention:   retention,
		lastCleanup: time.Now(),
	}
}

package ss2022

import (
	"sync"
	"time"
)

// SaltPool stores salts for [retention, 2*retention) to protect against replay attacks
// during the replay window.
type SaltPool[T comparable] struct {
	mu        sync.RWMutex
	pool      map[T]time.Time
	retention time.Duration
	lastClean time.Time
}

// clean removes expired salts from the pool,
// if the amount of time since the last cleanup exceeds retention.
func (p *SaltPool[T]) clean(now time.Time) {
	if now.Sub(p.lastClean) > p.retention {
		for salt, added := range p.pool {
			if now.Sub(added) > p.retention {
				delete(p.pool, salt)
			}
		}
		p.lastClean = now
	}
}

// Check returns whether the given salt is valid (not in the pool).
func (p *SaltPool[T]) Check(salt T) bool {
	p.mu.RLock()
	_, ok := p.pool[salt]
	p.mu.RUnlock()
	return !ok
}

// TryCheck is like Check, but it immediately returns true if the pool is contended.
func (p *SaltPool[T]) TryCheck(salt T) bool {
	if p.mu.TryRLock() {
		_, ok := p.pool[salt]
		p.mu.RUnlock()
		return !ok
	}
	return true
}

// Add cleans the pool, checks if the salt already exists in the pool,
// and adds the salt to the pool if the salt is not already in the pool.
// It returns true if the salt was added, false if it already exists.
func (p *SaltPool[T]) Add(now time.Time, salt T) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clean(now)
	if _, ok := p.pool[salt]; ok {
		return false
	}
	p.pool[salt] = now
	return true
}

// NewSaltPool returns a new salt pool with the given retention as the minimum amount of time
// for which an added salt is guaranteed to be kept in the pool.
func NewSaltPool[T comparable](retention time.Duration) *SaltPool[T] {
	return &SaltPool[T]{
		pool:      make(map[T]time.Time),
		retention: retention,
		lastClean: time.Now(),
	}
}

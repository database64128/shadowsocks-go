package ss2022

import "time"

// SaltPool stores salts for [retention, 2*retention) to protect against replay attacks
// during the replay window.
//
// SaltPool is not safe for concurrent use.
type SaltPool[T comparable] struct {
	pool      map[T]time.Time
	retention time.Duration
	lastClean time.Time
}

// clean removes expired salts from the pool.
func (p *SaltPool[T]) clean() {
	if now := time.Now(); now.Sub(p.lastClean) > p.retention {
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
	p.clean()
	_, ok := p.pool[salt]
	return !ok
}

// Add adds the given salt to the pool.
func (p *SaltPool[T]) Add(salt T) {
	p.pool[salt] = time.Now()
}

// NewSaltPool returns a new SaltPool with the given retention.
func NewSaltPool[T comparable](retention time.Duration) *SaltPool[T] {
	return &SaltPool[T]{
		pool:      make(map[T]time.Time),
		retention: retention,
		lastClean: time.Now(),
	}
}

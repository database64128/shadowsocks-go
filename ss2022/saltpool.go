package ss2022

import (
	"sync"
	"time"
)

// SaltPool stores salts for [ReplayWindowDuration] to protect against replay attacks
// during the replay window.
type SaltPool struct {
	mu         sync.RWMutex
	nodeBySalt map[[32]byte]*saltNode

	// head is the oldest node.
	head *saltNode
	// tail is the newest node.
	tail *saltNode
}

type saltNode struct {
	next      *saltNode
	salt      [32]byte
	expiresAt time.Time
}

// Contains returns whether the pool contains the given salt.
func (p *SaltPool) Contains(salt [32]byte) bool {
	p.mu.RLock()
	_, ok := p.nodeBySalt[salt]
	p.mu.RUnlock()
	return ok
}

// TryContains is like Contains, but it immediately returns false if the pool is contended.
func (p *SaltPool) TryContains(salt [32]byte) bool {
	if p.mu.TryRLock() {
		_, ok := p.nodeBySalt[salt]
		p.mu.RUnlock()
		return ok
	}
	return false
}

// Add adds the salt to the pool if it is not already in the pool.
// It returns true if the salt was added, false if it already exists.
func (p *SaltPool) Add(now time.Time, salt [32]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneExpired(now)
	if _, ok := p.nodeBySalt[salt]; ok {
		return false
	}
	p.insert(now, salt)
	return true
}

// Clear removes all salts from the pool.
func (p *SaltPool) Clear() {
	p.mu.Lock()
	clear(p.nodeBySalt)
	p.head = nil
	p.tail = nil
	p.mu.Unlock()
}

// pruneExpired removes all expired salts from the pool.
func (p *SaltPool) pruneExpired(now time.Time) {
	node := p.head
	if node == nil || node.expiresAt.After(now) {
		return
	}
	for {
		delete(p.nodeBySalt, node.salt)
		node = node.next
		if node == nil {
			p.head = nil
			p.tail = nil
			return
		}
		if node.expiresAt.After(now) {
			p.head = node
			return
		}
	}
}

// insert adds the new salt to the pool.
func (p *SaltPool) insert(now time.Time, salt [32]byte) {
	node := &saltNode{
		salt:      salt,
		expiresAt: now.Add(ReplayWindowDuration),
	}
	p.nodeBySalt[salt] = node
	if p.tail != nil {
		p.tail.next = node
	} else {
		p.head = node
	}
	p.tail = node
}

// NewSaltPool returns a new salt pool.
func NewSaltPool() *SaltPool {
	return &SaltPool{
		nodeBySalt: make(map[[32]byte]*saltNode),
	}
}

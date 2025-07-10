package cache

import (
	"iter"
	"math"
)

// Entry represents a key-value pair in the cache.
type Entry[K comparable, V any] struct {
	Key   K
	Value V
}

type boundedNode[K comparable, V any] struct {
	prev *boundedNode[K, V]
	next *boundedNode[K, V]
	Entry[K, V]
}

// BoundedCache is a simple in-memory cache with a fixed upper bound on the number of entries.
// It uses a doubly linked list to maintain the order of access, where the tail is the most recently used node.
// When the cache reaches its capacity, insertions will evict the least recently used node (the head of the list).
type BoundedCache[K comparable, V any] struct {
	nodeByKey map[K]*boundedNode[K, V]
	capacity  int

	// head is the least recently used node.
	head *boundedNode[K, V]
	// tail is the most recently used node.
	tail *boundedNode[K, V]
}

// NewBoundedCache returns a new bounded cache with the given capacity.
// If capacity is not positive, the cache will be effectively unbounded.
func NewBoundedCache[K comparable, V any](capacity int) *BoundedCache[K, V] {
	if capacity <= 0 {
		capacity = math.MaxInt
	}
	return &BoundedCache[K, V]{
		nodeByKey: make(map[K]*boundedNode[K, V]),
		capacity:  capacity,
	}
}

// Len returns the number of entries in the cache.
func (c *BoundedCache[K, V]) Len() int {
	return len(c.nodeByKey)
}

// Capacity returns the maximum number of entries the cache can hold.
func (c *BoundedCache[K, V]) Capacity() int {
	return c.capacity
}

// Contains returns whether the cache contains the given key.
//
// Unlike Get, this method does not update the access order of the cache.
func (c *BoundedCache[K, V]) Contains(key K) bool {
	_, ok := c.nodeByKey[key]
	return ok
}

// Get returns the value associated with key.
func (c *BoundedCache[K, V]) Get(key K) (value V, ok bool) {
	node, ok := c.nodeByKey[key]
	if !ok {
		return value, false
	}
	c.moveToTail(node)
	return node.Value, true
}

// GetEntry returns the entry associated with key.
func (c *BoundedCache[K, V]) GetEntry(key K) (entry *Entry[K, V], ok bool) {
	node, ok := c.nodeByKey[key]
	if !ok {
		return nil, false
	}
	c.moveToTail(node)
	return &node.Entry, true
}

// Set inserts or updates the value associated with key.
func (c *BoundedCache[K, V]) Set(key K, value V) {
	node, ok := c.nodeByKey[key]
	if !ok {
		c.insert(key, value)
		return
	}
	node.Value = value
	c.moveToTail(node)
}

// Insert adds a new key-value pair to the cache if the key does not already exist.
// It returns true if the insertion was successful, false if the key already exists.
func (c *BoundedCache[K, V]) Insert(key K, value V) bool {
	if _, ok := c.nodeByKey[key]; ok {
		return false
	}
	c.insert(key, value)
	return true
}

// InsertUnchecked adds a new key-value pair to the cache without checking if the key already exists.
//
// WARNING: This is undefined behavior if the key already exists in the cache.
func (c *BoundedCache[K, V]) InsertUnchecked(key K, value V) {
	c.insert(key, value)
}

// Remove deletes the value associated with key and returns whether the key was found.
func (c *BoundedCache[K, V]) Remove(key K) bool {
	node, ok := c.nodeByKey[key]
	if !ok {
		return false
	}
	c.remove(node)
	return true
}

// Clear removes all entries from the cache.
func (c *BoundedCache[K, V]) Clear() {
	clear(c.nodeByKey)
	c.head = nil
	c.tail = nil
}

// All returns an iterator over all entries in the cache,
// starting from the least recently used (head) to the most recently used (tail).
func (c *BoundedCache[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for node := c.head; node != nil; node = node.next {
			if !yield(node.Key, node.Value) {
				break
			}
		}
	}
}

// Backward returns an iterator over all entries in the cache,
// starting from the most recently used (tail) to the least recently used (head).
func (c *BoundedCache[K, V]) Backward() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for node := c.tail; node != nil; node = node.prev {
			if !yield(node.Key, node.Value) {
				break
			}
		}
	}
}

// insert inserts the key-value pair as a new node at the tail of the list.
func (c *BoundedCache[K, V]) insert(key K, value V) {
	// If the cache is at capacity, remove the least recently used item.
	if len(c.nodeByKey) == c.capacity {
		c.remove(c.head)
	}

	node := &boundedNode[K, V]{
		prev:  c.tail,
		Entry: Entry[K, V]{Key: key, Value: value},
	}

	c.nodeByKey[key] = node

	if c.tail != nil {
		c.tail.next = node
	} else {
		c.head = node
	}
	c.tail = node
}

// moveToTail promotes the given node to the tail of the list,
// indicating that it was recently accessed.
func (c *BoundedCache[K, V]) moveToTail(node *boundedNode[K, V]) {
	// Check if the node is already at the tail.
	if node.next == nil {
		return
	}

	// Detach from the list.
	node.next.prev = node.prev
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		c.head = node.next
	}

	// Attach to the tail.
	node.prev = c.tail
	node.next = nil
	c.tail.next = node
	c.tail = node
}

// remove deletes the given node from the cache.
func (c *BoundedCache[K, V]) remove(node *boundedNode[K, V]) {
	delete(c.nodeByKey, node.Key)

	if node.prev != nil {
		node.prev.next = node.next
	} else {
		c.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		c.tail = node.prev
	}
}

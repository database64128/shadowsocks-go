package bitset

import (
	"fmt"
	"math/bits"
)

const blockBits = bits.UintSize

// BitSet is a set of bits.
type BitSet struct {
	blocks   []uint
	capacity uint
}

// NewBitSet returns a new BitSet with the given capacity.
func NewBitSet(capacity uint) BitSet {
	return BitSet{
		blocks:   make([]uint, (capacity+blockBits-1)/blockBits),
		capacity: capacity,
	}
}

// Capacity returns the capacity of the BitSet.
func (s BitSet) Capacity() uint {
	return s.capacity
}

// Count returns the number of bits set to 1.
func (s BitSet) Count() (count uint) {
	for i := range s.blocks {
		count += uint(bits.OnesCount(s.blocks[i]))
	}
	return
}

func (s BitSet) checkIndex(index uint) {
	if index >= s.capacity {
		panic(fmt.Sprintf("bitset: index out of range [%d] with capacity %d", index, s.capacity))
	}
}

func (s BitSet) blockIndex(index uint) uint {
	return index / blockBits
}

func (s BitSet) bitIndex(index uint) uint {
	return index % blockBits
}

// IsSet returns whether the bit at the given index is set to 1.
func (s BitSet) IsSet(index uint) bool {
	s.checkIndex(index)
	return s.blocks[s.blockIndex(index)]&(1<<s.bitIndex(index)) != 0
}

// Set sets the bit at the given index to 1.
func (s *BitSet) Set(index uint) {
	s.checkIndex(index)
	s.blocks[s.blockIndex(index)] |= 1 << s.bitIndex(index)
}

// Unset sets the bit at the given index to 0.
func (s *BitSet) Unset(index uint) {
	s.checkIndex(index)
	s.blocks[s.blockIndex(index)] &^= 1 << s.bitIndex(index)
}

// Flip flips the bit at the given index.
func (s *BitSet) Flip(index uint) {
	s.checkIndex(index)
	s.blocks[s.blockIndex(index)] ^= 1 << s.bitIndex(index)
}

// SetAll sets all bits to 1.
func (s *BitSet) SetAll() {
	fullBlocks := s.blockIndex(s.capacity)
	for i := range s.blocks[:fullBlocks] {
		s.blocks[i] = ^uint(0)
	}
	if fullBlocks < uint(len(s.blocks)) {
		s.blocks[fullBlocks] = ^(^uint(0) << s.bitIndex(s.capacity))
	}
}

// UnsetAll sets all bits to 0.
func (s *BitSet) UnsetAll() {
	for i := range s.blocks {
		s.blocks[i] = 0
	}
}

// FlipAll flips all bits.
func (s *BitSet) FlipAll() {
	fullBlocks := s.blockIndex(s.capacity)
	for i := range s.blocks[:fullBlocks] {
		s.blocks[i] = ^s.blocks[i]
	}
	if fullBlocks < uint(len(s.blocks)) {
		s.blocks[fullBlocks] ^= ^(^uint(0) << s.bitIndex(s.capacity))
	}
}

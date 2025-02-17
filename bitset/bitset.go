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
	for _, block := range s.blocks {
		count += uint(bits.OnesCount(block))
	}
	return
}

func (s BitSet) checkIndex(index uint) {
	if index >= s.capacity {
		panic(fmt.Sprintf("bitset: index out of range [%d] with capacity %d", index, s.capacity))
	}
}

func blockIndex(index uint) uint {
	return index / blockBits
}

func bitIndex(index uint) uint {
	return index % blockBits
}

// IsSet returns whether the bit at the given index is set to 1.
func (s BitSet) IsSet(index uint) bool {
	s.checkIndex(index)
	return s.blocks[blockIndex(index)]&(1<<bitIndex(index)) != 0
}

// Set sets the bit at the given index to 1.
func (s BitSet) Set(index uint) {
	s.checkIndex(index)
	s.blocks[blockIndex(index)] |= 1 << bitIndex(index)
}

// Unset sets the bit at the given index to 0.
func (s BitSet) Unset(index uint) {
	s.checkIndex(index)
	s.blocks[blockIndex(index)] &^= 1 << bitIndex(index)
}

// Flip flips the bit at the given index.
func (s BitSet) Flip(index uint) {
	s.checkIndex(index)
	s.blocks[blockIndex(index)] ^= 1 << bitIndex(index)
}

// SetAll sets all bits to 1.
func (s BitSet) SetAll() {
	fullBlockCount := blockIndex(s.capacity)
	fullBlocks := s.blocks[:fullBlockCount]
	for i := range fullBlocks {
		fullBlocks[i] = ^uint(0)
	}
	if fullBlockCount < uint(len(s.blocks)) {
		s.blocks[fullBlockCount] = ^(^uint(0) << bitIndex(s.capacity))
	}
}

// UnsetAll sets all bits to 0.
func (s BitSet) UnsetAll() {
	clear(s.blocks)
}

// FlipAll flips all bits.
func (s BitSet) FlipAll() {
	fullBlockCount := blockIndex(s.capacity)
	fullBlocks := s.blocks[:fullBlockCount]
	for i := range fullBlocks {
		fullBlocks[i] = ^fullBlocks[i]
	}
	if fullBlockCount < uint(len(s.blocks)) {
		s.blocks[fullBlockCount] ^= ^(^uint(0) << bitIndex(s.capacity))
	}
}

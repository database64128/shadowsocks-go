package ss2022

import "math/bits"

const swfBlockBits = bits.UintSize

// SlidingWindowFilter maintains a sliding window of uint64 counters.
type SlidingWindowFilter struct {
	size               uint64
	last               uint64
	ring               []uint
	ringBlockIndexMask uint64
}

// NewSlidingWindowFilter returns a new sliding window filter with the given size.
func NewSlidingWindowFilter(size uint64) *SlidingWindowFilter {
	ringBits := uint64(1 << bits.Len64(size+swfBlockBits-1))
	ringBlocks := ringBits / swfBlockBits
	return &SlidingWindowFilter{
		size:               size,
		ring:               make([]uint, ringBlocks),
		ringBlockIndexMask: ringBlocks - 1,
	}
}

// Size returns the size of the sliding window.
func (f *SlidingWindowFilter) Size() uint64 {
	return f.size
}

// Reset resets the filter to its initial state.
func (f *SlidingWindowFilter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

func (*SlidingWindowFilter) unmaskedBlockIndex(counter uint64) uint64 {
	return counter / swfBlockBits
}

func (f *SlidingWindowFilter) blockIndex(counter uint64) uint64 {
	return counter / swfBlockBits & f.ringBlockIndexMask
}

func (*SlidingWindowFilter) bitIndex(counter uint64) uint64 {
	return counter % swfBlockBits
}

// IsOk checks whether counter can be accepted by the sliding window filter.
func (f *SlidingWindowFilter) IsOk(counter uint64) bool {
	// Accept counter if it is ahead of window.
	if counter > f.last {
		return true
	}

	// Reject counter if it is behind window.
	if f.last-counter >= f.size {
		return false
	}

	// Within window, accept if not seen by window.
	return f.ring[f.blockIndex(counter)]&(1<<f.bitIndex(counter)) == 0
}

// MustAdd adds counter to the sliding window without checking if the counter is valid.
// Call IsOk beforehand to make sure the counter is valid.
func (f *SlidingWindowFilter) MustAdd(counter uint64) {
	blockIndex := f.unmaskedBlockIndex(counter)

	// When counter is ahead of window, clear blocks ahead.
	if counter > f.last {
		lastBlockIndex := f.unmaskedBlockIndex(f.last)
		clearBlockCount := int(blockIndex - lastBlockIndex)
		if clearBlockCount > len(f.ring) {
			clearBlockCount = len(f.ring)
		}

		// Clear blocks ahead.
		for i := 0; i < clearBlockCount; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & f.ringBlockIndexMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter
	}

	blockIndex &= f.ringBlockIndexMask
	f.ring[blockIndex] |= 1 << f.bitIndex(counter)
}

// Add attempts to add counter to the sliding window and returns
// whether the counter is successfully added to the sliding window.
func (f *SlidingWindowFilter) Add(counter uint64) bool {
	unmaskedBlockIndex := f.unmaskedBlockIndex(counter)
	blockIndex := unmaskedBlockIndex & f.ringBlockIndexMask
	bitIndex := f.bitIndex(counter)

	switch {
	case counter > f.last: // Ahead of window, clear blocks ahead.
		lastBlockIndex := f.unmaskedBlockIndex(f.last)
		clearBlockCount := int(unmaskedBlockIndex - lastBlockIndex)
		if clearBlockCount > len(f.ring) {
			clearBlockCount = len(f.ring)
		}

		// Clear blocks ahead.
		for i := 0; i < clearBlockCount; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & f.ringBlockIndexMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter

	case f.last-counter >= f.size: // Behind window.
		return false

	case f.ring[blockIndex]&(1<<bitIndex) != 0: // Within window, already seen.
		return false
	}

	f.ring[blockIndex] |= 1 << bitIndex
	return true
}

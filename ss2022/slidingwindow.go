package ss2022

const (
	swBlockBitLog = 6                  // 1<<6 == 64 bits
	swBlockBits   = 1 << swBlockBitLog // must be power of 2
	swRingBlocks  = 1 << 7             // must be power of 2
	swBlockMask   = swRingBlocks - 1
	swBitMask     = swBlockBits - 1
	swSize        = (swRingBlocks - 1) * swBlockBits
)

// Filter maintains a sliding window of uint64 counters.
type Filter struct {
	last uint64
	ring [swRingBlocks]uint64
}

// Reset resets the filter to its initial state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

// IsOk checks whether counter can be accepted by the sliding window filter.
func (f *Filter) IsOk(counter uint64) bool {
	switch {
	case counter > f.last: // ahead of window
		return true
	case f.last-counter > swSize: // behind window
		return false
	}

	// In window. Check bit.
	blockIndex := counter >> swBlockBitLog & swBlockMask
	bitIndex := counter & swBitMask
	return f.ring[blockIndex]>>bitIndex&1 == 0
}

// MustAdd adds counter to the sliding window without checking if the counter is valid.
// Call IsOk beforehand to make sure the counter is valid.
func (f *Filter) MustAdd(counter uint64) {
	blockIndex := counter >> swBlockBitLog

	// Check if counter is ahead of window.
	if counter > f.last {
		lastBlockIndex := f.last >> swBlockBitLog
		diff := int(blockIndex - lastBlockIndex)
		if diff > swRingBlocks {
			diff = swRingBlocks
		}

		for i := 0; i < diff; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & swBlockMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter
	}

	blockIndex &= swBlockMask
	bitIndex := counter & swBitMask
	f.ring[blockIndex] |= 1 << bitIndex
}

// Add attempts to add counter to the sliding window and returns
// whether the counter is successfully added to the sliding window.
func (f *Filter) Add(counter uint64) bool {
	unmaskedBlockIndex := counter >> swBlockBitLog
	blockIndex := unmaskedBlockIndex & swBlockMask
	bitIndex := counter & swBitMask

	switch {
	case counter > f.last: // ahead of window
		lastBlockIndex := f.last >> swBlockBitLog
		diff := int(unmaskedBlockIndex - lastBlockIndex)
		if diff > swRingBlocks {
			diff = swRingBlocks
		}

		for i := 0; i < diff; i++ {
			lastBlockIndex = (lastBlockIndex + 1) & swBlockMask
			f.ring[lastBlockIndex] = 0
		}

		f.last = counter

	case f.last-counter > swSize: // behind window
		return false

	case f.ring[blockIndex]>>bitIndex&1 == 1: // already seen by window
		return false
	}

	f.ring[blockIndex] |= 1 << bitIndex
	return true
}

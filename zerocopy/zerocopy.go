// Package zerocopy defines interfaces and helper functions for zero-copy read/write operations.
package zerocopy

import "context"

// Headroom reports the amount of extra space required in read/write buffers besides the payload.
type Headroom struct {
	// Front is the minimum space required at the beginning of the buffer before payload.
	Front int

	// Rear is the minimum space required at the end of the buffer after payload.
	Rear int
}

// MaxHeadroom returns the maximum front and rear headroom of the two headroom pairs.
func MaxHeadroom(first, second Headroom) Headroom {
	return Headroom{
		Front: max(first.Front, second.Front),
		Rear:  max(first.Rear, second.Rear),
	}
}

// UDPRelayHeadroom returns the packer headroom subtracted by the unpacker headroom.
func UDPRelayHeadroom(packerHeadroom, unpackerHeadroom Headroom) Headroom {
	return Headroom{
		Front: max(0, packerHeadroom.Front-unpackerHeadroom.Front),
		Rear:  max(0, packerHeadroom.Rear-unpackerHeadroom.Rear),
	}
}

// tester allows us to write test functions outside _test.go files without importing the testing package.
type tester interface {
	Context() context.Context
	Error(args ...any)
	Fatal(args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

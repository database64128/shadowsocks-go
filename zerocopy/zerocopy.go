// Package zerocopy defines interfaces and helper functions for zero-copy read/write operations.
package zerocopy

// Headroom reports the amount of extra space required in read/write buffers besides the payload.
type Headroom struct {
	// Front is the minimum space required at the beginning of the buffer before payload.
	Front int

	// Rear is the minimum space required at the end of the buffer after payload.
	Rear int
}

// MaxHeadroom returns the maximum front and rear headroom of the two headroom pairs.
func MaxHeadroom(first, second Headroom) Headroom {
	if first.Front < second.Front {
		first.Front = second.Front
	}
	if first.Rear < second.Rear {
		first.Rear = second.Rear
	}
	return first
}

// UDPRelayHeadroom returns the packer headroom subtracted by the unpacker headroom.
func UDPRelayHeadroom(packerHeadroom, unpackerHeadroom Headroom) Headroom {
	packerHeadroom.Front -= unpackerHeadroom.Front
	if packerHeadroom.Front < 0 {
		packerHeadroom.Front = 0
	}
	packerHeadroom.Rear -= unpackerHeadroom.Rear
	if packerHeadroom.Rear < 0 {
		packerHeadroom.Rear = 0
	}
	return packerHeadroom
}

// tester allows us to write test functions outside _test.go files without importing the testing package.
type tester interface {
	Error(args ...any)
	Fatal(args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

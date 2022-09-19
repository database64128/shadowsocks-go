// Package zerocopy defines interfaces and helper functions for zero-copy read/write operations.
package zerocopy

// Headroom is implemented by readers and writers that require extra buffer space as headroom in read/write calls.
type Headroom interface {
	// FrontHeadroom returns the minimum space required at the beginning of the buffer before payload.
	FrontHeadroom() int

	// RearHeadroom returns the minimum space required at the end of the buffer after payload.
	RearHeadroom() int
}

// ZeroHeadroom can be embedded by types that have zero headroom.
type ZeroHeadroom struct{}

// FrontHeadroom implements the Headroom FrontHeadroom method.
func (z ZeroHeadroom) FrontHeadroom() int {
	return 0
}

// RearHeadroom implements the Headroom RearHeadroom method.
func (z ZeroHeadroom) RearHeadroom() int {
	return 0
}

// tester allows us to write test functions outside _test.go files without importing the testing package.
type tester interface {
	Error(args ...any)
	Fatal(args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

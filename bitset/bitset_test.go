package bitset

import (
	"strconv"
	"testing"
)

func mustPanic(t *testing.T, f func(), name string) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s did not panic", name)
}

func testBitSetIndexOutOfRange(t *testing.T, s BitSet) {
	index := s.Capacity()
	mustPanic(t, func() { _ = s.IsSet(index) }, "s.IsSet(index)")
	mustPanic(t, func() { s.Set(index) }, "s.Set(index)")
	mustPanic(t, func() { s.Unset(index) }, "s.Unset(index)")
	mustPanic(t, func() { s.Flip(index) }, "s.Flip(index)")
}

func assertEmptyBitSet(t *testing.T, s BitSet) {
	t.Helper()
	if count := s.Count(); count != 0 {
		t.Errorf("expected count to be 0, got %d", count)
	}
	for i := range s.Capacity() {
		if s.IsSet(i) {
			t.Errorf("bit %d is unexpectedly set", i)
		}
	}
}

func assertOddBitSet(t *testing.T, s BitSet) {
	t.Helper()
	if count, expectedCount := s.Count(), s.Capacity()/2; count != expectedCount {
		t.Errorf("expected count to be %d, got %d", expectedCount, count)
	}
	for i := range s.Capacity() {
		if i%2 == 0 == s.IsSet(i) {
			t.Errorf("unexpected bit %d", i)
		}
	}
}

func assertEvenBitSet(t *testing.T, s BitSet) {
	t.Helper()
	if count, expectedCount := s.Count(), (s.Capacity()+1)/2; count != expectedCount {
		t.Errorf("expected count to be %d, got %d", expectedCount, count)
	}
	for i := range s.Capacity() {
		if i%2 == 1 == s.IsSet(i) {
			t.Errorf("unexpected bit %d", i)
		}
	}
}

func assertFullBitSet(t *testing.T, s BitSet) {
	t.Helper()
	if count := s.Count(); count != s.Capacity() {
		t.Errorf("expected count to be %d, got %d", s.Capacity(), count)
	}
	for i := range s.Capacity() {
		if !s.IsSet(i) {
			t.Errorf("bit %d is unexpectedly unset", i)
		}
	}
}

func clearBitSet(t *testing.T, s BitSet) {
	t.Helper()
	for i := range s.Capacity() {
		s.Unset(i)
	}
}

func fillOddBitSet(t *testing.T, s BitSet) {
	t.Helper()
	for i := range s.Capacity() {
		switch i % 2 {
		case 0:
			s.Unset(i)
		case 1:
			s.Set(i)
		}
	}
}

func fillEvenBitSet(t *testing.T, s BitSet) {
	t.Helper()
	for i := range s.Capacity() {
		switch i % 2 {
		case 0:
			s.Set(i)
		case 1:
			s.Unset(i)
		}
	}
}

func fillBitSet(t *testing.T, s BitSet) {
	t.Helper()
	for i := range s.Capacity() {
		s.Set(i)
	}
}

func testBitSetSetAll(t *testing.T, s BitSet) {
	clearBitSet(t, s)
	s.SetAll()
	assertFullBitSet(t, s)

	fillOddBitSet(t, s)
	s.SetAll()
	assertFullBitSet(t, s)

	fillEvenBitSet(t, s)
	s.SetAll()
	assertFullBitSet(t, s)

	fillBitSet(t, s)
	s.SetAll()
	assertFullBitSet(t, s)
}

func testBitSetUnsetAll(t *testing.T, s BitSet) {
	clearBitSet(t, s)
	s.UnsetAll()
	assertEmptyBitSet(t, s)

	fillOddBitSet(t, s)
	s.UnsetAll()
	assertEmptyBitSet(t, s)

	fillEvenBitSet(t, s)
	s.UnsetAll()
	assertEmptyBitSet(t, s)

	fillBitSet(t, s)
	s.UnsetAll()
	assertEmptyBitSet(t, s)
}

func testBitSetFlipAll(t *testing.T, s BitSet) {
	clearBitSet(t, s)
	s.FlipAll()
	assertFullBitSet(t, s)

	fillOddBitSet(t, s)
	s.FlipAll()
	assertEvenBitSet(t, s)

	fillEvenBitSet(t, s)
	s.FlipAll()
	assertOddBitSet(t, s)

	fillBitSet(t, s)
	s.FlipAll()
	assertEmptyBitSet(t, s)
}

func flipBitSet(t *testing.T, s BitSet) {
	t.Helper()
	for i := range s.Capacity() {
		s.Flip(i)
	}
}

func testBitSetFlip(t *testing.T, s BitSet) {
	clearBitSet(t, s)
	flipBitSet(t, s)
	assertFullBitSet(t, s)

	fillOddBitSet(t, s)
	flipBitSet(t, s)
	assertEvenBitSet(t, s)

	fillEvenBitSet(t, s)
	flipBitSet(t, s)
	assertOddBitSet(t, s)

	fillBitSet(t, s)
	flipBitSet(t, s)
	assertEmptyBitSet(t, s)
}

var bitSetTestCapacities = [...]uint{0, 1, 2, 31, 32, 33, 63, 64, 65, 254, 500, 3000}

func TestBitSet(t *testing.T) {
	for _, capacity := range bitSetTestCapacities {
		t.Run(strconv.FormatUint(uint64(capacity), 10), func(t *testing.T) {
			s := NewBitSet(capacity)
			t.Run("IndexOutOfRange", func(t *testing.T) {
				testBitSetIndexOutOfRange(t, s)
			})
			t.Run("SetAll", func(t *testing.T) {
				testBitSetSetAll(t, s)
			})
			t.Run("UnsetAll", func(t *testing.T) {
				testBitSetUnsetAll(t, s)
			})
			t.Run("FlipAll", func(t *testing.T) {
				testBitSetFlipAll(t, s)
			})
			t.Run("Flip", func(t *testing.T) {
				testBitSetFlip(t, s)
			})
		})
	}
}

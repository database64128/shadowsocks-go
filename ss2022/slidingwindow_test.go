package ss2022

import (
	"strconv"
	"testing"
)

func testIsOkMustAdd(t *testing.T, f *SlidingWindowFilter) {
	f.Reset()
	i := uint64(1)
	n := uint64(len(f.ring)+1) * swfBlockBits

	// Add 1, 3, 5, ..., n-1.
	for ; i < n; i += 2 {
		if !f.IsOk(i) {
			t.Error(i, "should be ok.")
		}
		f.MustAdd(i)
	}

	// Check 0, 2, 4, ..., 126.
	for i = 0; i < n-f.size; i += 2 {
		if f.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Check 128, 130, 132, ..., n-2.
	for ; i < n; i += 2 {
		if !f.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}

	// Check 1, 3, 5, ..., n-1.
	for i = 1; i < n; i += 2 {
		if f.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Roll over the window.
	n <<= 1
	if !f.IsOk(n) {
		t.Error(n, "should be ok.")
	}
	f.MustAdd(n)

	// Check behind window.
	for i = 0; i < n-f.size+1; i++ {
		if f.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Check within window.
	for ; i < n; i++ {
		if !f.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}

	// Check n.
	if i == n {
		if f.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
		i++
	}

	// Check after window.
	for ; i < n+f.size; i++ {
		if !f.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}
}

func testAdd(t *testing.T, f *SlidingWindowFilter) {
	f.Reset()
	i := uint64(1)
	n := uint64(len(f.ring)+1) * swfBlockBits

	// Add 1, 3, 5, ..., n-1.
	for ; i < n; i += 2 {
		if !f.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check 0, 2, 4, ..., 126.
	for i = 0; i < n-f.size; i += 2 {
		if f.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Check 128, 130, 132, ..., n-2.
	for ; i < n; i += 2 {
		if !f.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check 1, 3, 5, ..., n-1.
	for i = 1; i < n; i += 2 {
		if f.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Roll over the window.
	n <<= 1
	if !f.Add(n) {
		t.Error(n, "should succeed.")
	}

	// Check behind window.
	for i = 0; i < n-f.size+1; i++ {
		if f.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Check within window.
	for ; i < n; i++ {
		if !f.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check n.
	if i == n {
		if f.Add(i) {
			t.Error(i, "should fail.")
		}
		i++
	}

	// Check after window.
	for ; i < n+f.size; i++ {
		if !f.Add(i) {
			t.Error(i, "should succeed.")
		}
	}
}

func testReset(t *testing.T, f *SlidingWindowFilter) {
	n := f.Size() * 2

	for i := uint64(0); i < n; i++ {
		f.MustAdd(i)
	}

	f.Reset()

	for i := uint64(0); i < n; i++ {
		if !f.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}
}

func testSlidingWindowFilter(t *testing.T, f *SlidingWindowFilter) {
	t.Run("IsOkMustAdd", func(t *testing.T) {
		testIsOkMustAdd(t, f)
	})
	t.Run("Add", func(t *testing.T) {
		testAdd(t, f)
	})
	t.Run("Reset", func(t *testing.T) {
		testReset(t, f)
	})
}

func TestSlidingWindowFilter(t *testing.T) {
	sizes := []uint64{0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257}
	for _, size := range sizes {
		t.Run(strconv.FormatUint(size, 10), func(t *testing.T) {
			f := NewSlidingWindowFilter(size)
			t.Log("ringBlockIndexMask", f.ringBlockIndexMask)
			testSlidingWindowFilter(t, f)
		})
	}
}

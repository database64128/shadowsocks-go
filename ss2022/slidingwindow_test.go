package ss2022

import "testing"

func TestIsOkMustAdd(t *testing.T) {
	var (
		filter Filter
		n      uint64 = (swRingBlocks + 1) * swBlockBits
	)

	// Add 1, 3, 5, ..., n-1.
	for i := uint64(1); i < n; i += 2 {
		if !filter.IsOk(i) {
			t.Error(i, "should be ok.")
		}
		filter.MustAdd(i)
	}

	// Check 0, 2, 4, ..., 126.
	for i := uint64(1); i < n-swSize; i += 2 {
		if filter.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Check 128, 130, 132, ..., n-2.
	for i := uint64(n - swSize); i < n; i += 2 {
		if !filter.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}

	// Check 1, 3, 5, ..., n-1.
	for i := uint64(1); i < n; i += 2 {
		if filter.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Roll over the window.
	n *= 2
	if !filter.IsOk(n) {
		t.Error(n, "should be ok.")
	}
	filter.MustAdd(n)

	// Check behind window.
	for i := uint64(0); i < n-swSize; i++ {
		if filter.IsOk(i) {
			t.Error(i, "should not be ok.")
		}
	}

	// Check within window.
	for i := n - swSize; i < n; i++ {
		if !filter.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}

	// Check after window.
	for i := n + 1; i < n+swSize; i++ {
		if !filter.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}
}

func TestAdd(t *testing.T) {
	var (
		filter Filter
		n      uint64 = (swRingBlocks + 1) * swBlockBits
	)

	// Add 1, 3, 5, ..., n-1.
	for i := uint64(1); i < n; i += 2 {
		if !filter.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check 0, 2, 4, ..., 126.
	for i := uint64(1); i < n-swSize; i += 2 {
		if filter.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Check 128, 130, 132, ..., n-2.
	for i := uint64(n - swSize); i < n; i += 2 {
		if !filter.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check 1, 3, 5, ..., n-1.
	for i := uint64(1); i < n; i += 2 {
		if filter.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Roll over the window.
	n *= 2
	if !filter.Add(n) {
		t.Error(n, "should succeed.")
	}

	// Check behind window.
	for i := uint64(0); i < n-swSize; i++ {
		if filter.Add(i) {
			t.Error(i, "should fail.")
		}
	}

	// Check within window.
	for i := n - swSize; i < n; i++ {
		if !filter.Add(i) {
			t.Error(i, "should succeed.")
		}
	}

	// Check after window.
	for i := n + 1; i < n+swSize; i++ {
		if !filter.Add(i) {
			t.Error(i, "should succeed.")
		}
	}
}

func TestReset(t *testing.T) {
	var filter Filter

	for i := uint64(0); i < swSize*2; i++ {
		filter.MustAdd(i)
	}

	filter.Reset()

	for i := uint64(0); i < swSize*2; i++ {
		if !filter.IsOk(i) {
			t.Error(i, "should be ok.")
		}
	}
}

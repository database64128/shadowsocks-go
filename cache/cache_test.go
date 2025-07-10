package cache_test

import (
	"math"
	"slices"
	"testing"

	"github.com/database64128/shadowsocks-go/cache"
)

func TestBoundedCache(t *testing.T) {
	c := cache.NewBoundedCache[int, int](3)
	assertBoundedCacheLenCapacityContent(t, c, nil, 3)
	c.Set(1, -1)
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{1, -1}}, 3)
	if !c.Insert(2, -2) {
		t.Error("c.Insert(2, -2) = false, want true")
	}
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{1, -1}, {2, -2}}, 3)
	c.InsertUnchecked(3, -3)
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{1, -1}, {2, -2}, {3, -3}}, 3)
	c.Set(4, -4)
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{2, -2}, {3, -3}, {4, -4}}, 3)
	if value, ok := c.Get(2); value != -2 || !ok {
		t.Errorf("c.Get(2) = %d, %v, want -2, true", value, ok)
	}
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{3, -3}, {4, -4}, {2, -2}}, 3)
	if entry, ok := c.GetEntry(4); entry == nil || entry.Key != 4 || entry.Value != -4 || !ok {
		t.Errorf("c.GetEntry(4) = %v, %v, want {Key: 4, Value: -4}, true", entry, ok)
	}
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{3, -3}, {2, -2}, {4, -4}}, 3)
	if !c.Remove(4) {
		t.Error("c.Remove(4) = false, want true")
	}
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{3, -3}, {2, -2}}, 3)
	c.Set(2, 2)
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{3, -3}, {2, 2}}, 3)
	if value, ok := c.Get(3); value != -3 || !ok {
		t.Errorf("c.Get(3) = %d, %v, want -3, true", value, ok)
	}
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{{2, 2}, {3, -3}}, 3)
	c.Clear()
	assertBoundedCacheLenCapacityContent(t, c, nil, 3)
}

func TestBoundedCacheUnboundedCapacity(t *testing.T) {
	c := cache.NewBoundedCache[int, int](0)
	assertBoundedCacheLenCapacityContent(t, c, nil, math.MaxInt)
	c.Set(1, -1)
	c.Set(2, -2)
	c.Set(3, -3)
	for range c.All() {
		for range c.Backward() {
			break
		}
		break
	}
	c.Set(4, -4)
	c.Set(5, -5)
	c.Set(6, -6)
	assertBoundedCacheLenCapacityContent(t, c, []cache.Entry[int, int]{
		{1, -1}, {2, -2}, {3, -3}, {4, -4}, {5, -5}, {6, -6},
	}, math.MaxInt)
}

func assertBoundedCacheLenCapacityContent(t *testing.T, c *cache.BoundedCache[int, int], want []cache.Entry[int, int], expectedCapacity int) {
	t.Helper()

	if got := c.Len(); got != len(want) {
		t.Errorf("c.Len() = %d, want %d", got, len(want))
	}
	if got := c.Capacity(); got != expectedCapacity {
		t.Errorf("c.Capacity() = %d, want %d", got, expectedCapacity)
	}

	got := make([]cache.Entry[int, int], 0, len(want))
	for key, value := range c.All() {
		got = append(got, cache.Entry[int, int]{Key: key, Value: value})
	}
	if !slices.Equal(got, want) {
		t.Errorf("c.All() = %v, want %v", got, want)
	}

	got = got[:0]
	for key, value := range c.Backward() {
		got = append(got, cache.Entry[int, int]{Key: key, Value: value})
	}
	if !slicesReverseEqual(got, want) {
		t.Errorf("c.Backward() = %v, want %v", got, want)
	}

	for key := range 10 {
		if index := slices.IndexFunc(want, func(e cache.Entry[int, int]) bool {
			return e.Key == key
		}); index != -1 {
			expectedEntry := want[index]
			expectedValue := expectedEntry.Value

			if !c.Contains(key) {
				t.Errorf("c.Contains(%d) = false, want true", key)
			}

			if c.Insert(key, expectedValue) {
				t.Errorf("c.Insert(%d, %d) = true, want false", key, expectedValue)
			}
		} else {
			if c.Contains(key) {
				t.Errorf("c.Contains(%d) = true, want false", key)
			}

			value, ok := c.Get(key)
			if value != 0 || ok {
				t.Errorf("c.Get(%d) = %d, %v, want 0, false", key, value, ok)
			}

			entry, ok := c.GetEntry(key)
			if entry != nil || ok {
				t.Errorf("c.GetEntry(%d) = %v, %v, want nil, false", key, entry, ok)
			}

			if c.Remove(key) {
				t.Errorf("c.Remove(%d) = true, want false", key)
			}
		}
	}
}

func slicesReverseEqual[S ~[]E, E comparable](s1, s2 S) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[len(s2)-1-i] {
			return false
		}
	}
	return true
}

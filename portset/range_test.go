package portset

import (
	"strconv"
	"testing"
)

func TestPortRangeContains(t *testing.T) {
	r := PortRange{From: 16384, To: 32768}
	for i := uint(1); i < 16384; i++ {
		if r.Contains(uint16(i)) {
			t.Errorf("contains unexpected port %d", i)
		}
	}
	for i := uint(16384); i <= 32768; i++ {
		if !r.Contains(uint16(i)) {
			t.Errorf("expected port %d to be in range", i)
		}
	}
	for i := uint(32769); i < 65536; i++ {
		if r.Contains(uint16(i)) {
			t.Errorf("contains unexpected port %d", i)
		}
	}
}

// portRangeSetContains is a test helper function that uses linear search and
// [PortRange.Contains] to determine whether the given port is in the port range set.
func portRangeSetContains(s PortRangeSet, port uint16) bool {
	for _, r := range s.ranges {
		if r.Contains(port) {
			return true
		}
	}
	return false
}

func testPortRangeSetContains(t *testing.T, s PortRangeSet) {
	for i := uint(1); i < 65536; i++ {
		binarySearchContains := s.Contains(uint16(i))
		linearSearchContains := portRangeSetContains(s, uint16(i))
		if binarySearchContains != linearSearchContains {
			t.Errorf("mismatched results for port %d: binary search says %t, linear search says %t", i, binarySearchContains, linearSearchContains)
		}
	}
}

func TestPortRangeSetContains(t *testing.T) {
	testPortRangeSets := [...]PortRangeSet{
		{},
		{ranges: []PortRange{{From: 4096, To: 8192}}},
		{ranges: []PortRange{{From: 4096, To: 8192}, {From: 12288, To: 16384}}},
		{ranges: []PortRange{{From: 4096, To: 8192}, {From: 12288, To: 16384}, {From: 20480, To: 24576}}},
		{ranges: []PortRange{{From: 4096, To: 8192}, {From: 12288, To: 16384}, {From: 20480, To: 24576}, {From: 28672, To: 32768}}},
	}
	for i, s := range testPortRangeSets {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testPortRangeSetContains(t, s)
		})
	}
}

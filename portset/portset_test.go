package portset

import (
	"strconv"
	"testing"

	"github.com/database64128/shadowsocks-go/slices"
)

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic, got none")
		}
	}()
	f()
}

func TestPortSetBadPort(t *testing.T) {
	var s PortSet
	assertPanic(t, func() { s.Contains(0) })
	assertPanic(t, func() { s.Add(0) })
	assertPanic(t, func() { s.AddRange(0, 1) })
	assertPanic(t, func() { s.AddRange(1, 0) })
	assertPanic(t, func() { s.AddRange(1, 1) })
}

func assertPortSetFirst(t *testing.T, s *PortSet, from uint16) {
	t.Helper()
	if first := s.First(); first != from {
		t.Errorf("expected first to be %d, got %d", from, first)
	}
}

func TestPortSetEmptyFirst(t *testing.T) {
	var s PortSet
	assertPortSetFirst(t, &s, 0)
}

func assertPortSetCount(t *testing.T, s *PortSet, from, to uint16) {
	t.Helper()
	if count, expectedCount := s.Count(), uint(to-from)+1; count != expectedCount {
		t.Errorf("expected count to be %d, got %d", expectedCount, count)
	}
}

func assertPortSetSingleRange(t *testing.T, s *PortSet, from, to uint16) {
	t.Helper()
	if r := s.RangeSet(); len(r.ranges) != 1 || r.ranges[0].From != from || r.ranges[0].To != to {
		t.Errorf("expected single range %d-%d, got %v", from, to, r)
	}
}

func assertPortSetContainsSingleRange(t *testing.T, s *PortSet, from, to uint16) {
	t.Helper()
	for i := uint(1); i < uint(from); i++ {
		if s.Contains(uint16(i)) {
			t.Errorf("contains unexpected port %d", i)
		}
	}
	for i := uint(from); i <= uint(to); i++ {
		if !s.Contains(uint16(i)) {
			t.Errorf("expected port %d to be in set", i)
		}
	}
	for i := uint(to) + 1; i < 65536; i++ {
		if s.Contains(uint16(i)) {
			t.Errorf("contains unexpected port %d", i)
		}
	}
}

func portSetAddRange(s *PortSet, from, to uint16) {
	for i := uint(from); i <= uint(to); i++ {
		s.Add(uint16(i))
	}
}

func testPortSetSingleRange(t *testing.T, from, to uint16) {
	var s0, s1 PortSet

	s0.AddRange(from, to)
	assertPortSetFirst(t, &s0, from)
	assertPortSetCount(t, &s0, from, to)
	assertPortSetSingleRange(t, &s0, from, to)
	assertPortSetContainsSingleRange(t, &s0, from, to)

	portSetAddRange(&s1, from, to)
	if s0 != s1 {
		t.Error("expected AddRange to be equivalent to consecutive Add calls")
	}
}

func TestPortSetSingleRange(t *testing.T) {
	testRanges := [...]uint16{1, 2, 62, 63, 64, 65, 126, 127, 128, 129, 254, 255, 256, 257, 65534, 65535}
	for _, from := range testRanges {
		for _, to := range testRanges {
			if from >= to {
				continue
			}
			t.Run(strconv.FormatUint(uint64(from), 10)+"-"+strconv.FormatUint(uint64(to), 10), func(t *testing.T) {
				testPortSetSingleRange(t, from, to)
			})
		}
	}
}

func testPortSetMultipleRanges(t *testing.T, portRangeSet PortRangeSet) {
	var portSet PortSet
	for _, r := range portRangeSet.ranges {
		portSet.AddRange(r.From, r.To)
	}

	for i := uint(1); i < 65536; i++ {
		portSetContains := portSet.Contains(uint16(i))
		portRangeSetContains := portRangeSet.Contains(uint16(i))
		if portSetContains != portRangeSetContains {
			t.Errorf("mismatched results for port %d: portSet says %t, portRangeSet says %t", i, portSetContains, portRangeSetContains)
		}
	}

	if portSetRangeCount := portSet.RangeCount(); portSetRangeCount != uint(len(portRangeSet.ranges)) {
		t.Errorf("expected range count to be %d, got %d", len(portRangeSet.ranges), portSetRangeCount)
	}

	if portSetRangeSet := portSet.RangeSet(); !slices.Equal(portSetRangeSet.ranges, portRangeSet.ranges) {
		t.Errorf("expected ranges to be %v, got %v", portRangeSet.ranges, portSetRangeSet.ranges)
	}
}

func TestPortSetMultipleRanges(t *testing.T) {
	testPortRangeSets := [...]PortRangeSet{
		{},
		{ranges: []PortRange{{From: 62, To: 63}}},
		{ranges: []PortRange{{From: 62, To: 64}}},
		{ranges: []PortRange{{From: 62, To: 65}}},
		{ranges: []PortRange{{From: 62, To: 126}}},
		{ranges: []PortRange{{From: 62, To: 127}}},
		{ranges: []PortRange{{From: 62, To: 128}}},
		{ranges: []PortRange{{From: 62, To: 129}}},
		{ranges: []PortRange{{From: 62, To: 254}}},
		{ranges: []PortRange{{From: 62, To: 255}}},
		{ranges: []PortRange{{From: 62, To: 256}}},
		{ranges: []PortRange{{From: 62, To: 257}}},
		{ranges: []PortRange{{From: 62, To: 63}, {From: 126, To: 127}}},
		{ranges: []PortRange{{From: 62, To: 64}, {From: 126, To: 128}}},
		{ranges: []PortRange{{From: 62, To: 65}, {From: 126, To: 129}}},
		{ranges: []PortRange{{From: 62, To: 63}, {From: 126, To: 127}, {From: 254, To: 255}}},
		{ranges: []PortRange{{From: 62, To: 64}, {From: 126, To: 128}, {From: 254, To: 256}}},
		{ranges: []PortRange{{From: 62, To: 65}, {From: 126, To: 129}, {From: 254, To: 257}}},
	}
	for i, portRangeSet := range testPortRangeSets {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testPortSetMultipleRanges(t, portRangeSet)
		})
	}
}

func testPortSetParse(t *testing.T, portSetString string, expectedNoError bool, expectedRanges []PortRange) {
	var portSet PortSet
	if err := portSet.Parse(portSetString); (err == nil) != expectedNoError {
		t.Errorf("unexpected error: %v", err)
	}
	if rangeSet := portSet.RangeSet(); !slices.Equal(rangeSet.ranges, expectedRanges) {
		t.Errorf("expected ranges to be %v, got %v", expectedRanges, rangeSet.ranges)
	}
}

func TestPortSetParse(t *testing.T) {
	testData := []struct {
		portSetString   string
		expectedNoError bool
		expectedRanges  []PortRange
	}{
		{"", true, []PortRange{}},
		{"1", true, []PortRange{{From: 1, To: 1}}},
		{"1,", true, []PortRange{{From: 1, To: 1}}},
		{"1,1", true, []PortRange{{From: 1, To: 1}}},
		{"1,2", true, []PortRange{{From: 1, To: 2}}},
		{"1-2", true, []PortRange{{From: 1, To: 2}}},
		{"1-2,3", true, []PortRange{{From: 1, To: 3}}},
		{"1-2,3-4", true, []PortRange{{From: 1, To: 4}}},
		{"1-4,2,3", true, []PortRange{{From: 1, To: 4}}},
		{"1-4,2-3", true, []PortRange{{From: 1, To: 4}}},
		{"1,2,4,5", true, []PortRange{{From: 1, To: 2}, {From: 4, To: 5}}},
		{"1-2,4-5", true, []PortRange{{From: 1, To: 2}, {From: 4, To: 5}}},
		{"1-65535", true, []PortRange{{From: 1, To: 65535}}},
		{"0", false, []PortRange{}},
		{"0,1", false, []PortRange{}},
		{"0-1", false, []PortRange{}},
		{"1-0", false, []PortRange{}},
		{"2-1", false, []PortRange{}},
		{"1-65536", false, []PortRange{}},
		{"1-65535,65536", false, []PortRange{{From: 1, To: 65535}}},
		{"abc", false, []PortRange{}},
		{"1-abc", false, []PortRange{}},
		{"abc-1", false, []PortRange{}},
		{",", false, []PortRange{}},
		{"-", false, []PortRange{}},
		{",1", false, []PortRange{}},
		{"-1", false, []PortRange{}},
		{"1-", false, []PortRange{}},
		{"1-,", false, []PortRange{}},
		{"1,-", false, []PortRange{{From: 1, To: 1}}},
		{",-1", false, []PortRange{}},
		{"-,1", false, []PortRange{}},
	}
	for i, data := range testData {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			testPortSetParse(t, data.portSetString, data.expectedNoError, data.expectedRanges)
		})
	}
}

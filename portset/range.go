package portset

// PortRange is an inclusive range of ports.
type PortRange struct {
	From uint16
	To   uint16
}

// Contains returns whether the given port is in the range.
func (r PortRange) Contains(port uint16) bool {
	return r.From <= port && port <= r.To
}

// PortRangeSet is a set of port ranges.
type PortRangeSet struct {
	ranges []PortRange
}

// Contains returns whether the given port is in the set.
func (s PortRangeSet) Contains(port uint16) bool {
	i, j := 0, len(s.ranges)
	for i < j {
		h := int(uint(i+j) >> 1)
		switch {
		case port > s.ranges[h].To:
			i = h + 1
		case port < s.ranges[h].From:
			j = h
		default:
			return true
		}
	}
	return false
}

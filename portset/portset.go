package portset

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

const blockBits = bits.UintSize

var ErrZeroPort = errors.New("port number cannot be zero")

// PortSet is a bit set for ports.
type PortSet struct {
	blocks [65536 / blockBits]uint
}

// Count returns the number of ports in the set.
func (s *PortSet) Count() (count uint) {
	for _, block := range s.blocks {
		count += uint(bits.OnesCount(block))
	}
	return
}

// First returns the first port in the set.
func (s *PortSet) First() uint16 {
	for i, block := range s.blocks {
		if block == 0 {
			continue
		}
		return uint16(i*blockBits + bits.TrailingZeros(block))
	}
	return 0
}

// RangeCount returns the number of port ranges in the set.
func (s *PortSet) RangeCount() (count uint) {
	var inRange bool
	for _, block := range s.blocks {
		bitsRemaining := uint(blockBits)
		for {
			trailingZeros := uint(bits.TrailingZeros(block))
			if trailingZeros != 0 {
				if inRange {
					inRange = false
				}
				if trailingZeros >= bitsRemaining {
					break
				}
				block >>= trailingZeros
				bitsRemaining -= trailingZeros
			}

			trailingOnes := uint(bits.TrailingZeros(^block))
			if !inRange {
				inRange = true
				count++
			}
			if trailingOnes == bitsRemaining {
				break
			}
			block >>= trailingOnes
			bitsRemaining -= trailingOnes
		}
	}
	return
}

// RangeSet returns the ports in the set as a port range set.
func (s *PortSet) RangeSet() PortRangeSet {
	// [PortRange] is a small struct, so we can afford to preallocate the slice.
	// Use 16 as the initial capacity, which corresponds to a 64-byte backing array,
	// which happens to be the most common cache line size on modern CPUs.
	ranges := make([]PortRange, 0, 16)

	var (
		inRange bool
		from    uint16
	)

	for i, block := range s.blocks {
		bitsRemaining := uint(blockBits)
		for {
			trailingZeros := uint(bits.TrailingZeros(block))
			if trailingZeros != 0 {
				if inRange {
					inRange = false
					ranges = append(ranges, PortRange{From: from, To: uint16((uint(i)+1)*blockBits - bitsRemaining - 1)})
				}
				if trailingZeros >= bitsRemaining {
					break
				}
				block >>= trailingZeros
				bitsRemaining -= trailingZeros
			}

			trailingOnes := uint(bits.TrailingZeros(^block))
			if !inRange {
				inRange = true
				from = uint16((uint(i)+1)*blockBits - bitsRemaining)
			}
			if trailingOnes == bitsRemaining {
				break
			}
			block >>= trailingOnes
			bitsRemaining -= trailingOnes
		}
	}

	if inRange {
		ranges = append(ranges, PortRange{From: from, To: 65535})
	}

	return PortRangeSet{ranges: ranges}
}

func panicOnZeroPort(port uint) {
	if port == 0 {
		panic(ErrZeroPort)
	}
}

func (s *PortSet) blockIndex(port uint) uint {
	return port / blockBits
}

func (s *PortSet) bitIndex(port uint) uint {
	return port % blockBits
}

// Contains returns whether the given port is in the set.
func (s *PortSet) Contains(port uint16) bool {
	p := uint(port)
	panicOnZeroPort(p)
	return s.blocks[s.blockIndex(p)]&(1<<s.bitIndex(p)) != 0
}

func (s *PortSet) add(port uint) {
	s.blocks[s.blockIndex(port)] |= 1 << s.bitIndex(port)
}

// Add adds the given port to the set.
func (s *PortSet) Add(port uint16) {
	p := uint(port)
	panicOnZeroPort(p)
	s.add(p)
}

func (s *PortSet) addRange(fromInclusive, toExclusive uint) {
	fromBlockIndex := s.blockIndex(fromInclusive)
	fromBitIndex := s.bitIndex(fromInclusive)
	toBlockIndex := s.blockIndex(toExclusive)
	toBitIndex := s.bitIndex(toExclusive)

	fromBlockMask := ^uint(0) << fromBitIndex
	toBlockMask := ^(^uint(0) << toBitIndex)

	if fromBlockIndex == toBlockIndex {
		s.blocks[fromBlockIndex] |= fromBlockMask & toBlockMask
		return
	}

	s.blocks[fromBlockIndex] |= fromBlockMask
	for i := fromBlockIndex + 1; i < toBlockIndex; i++ {
		s.blocks[i] = ^uint(0)
	}
	if toBlockIndex < uint(len(s.blocks)) {
		s.blocks[toBlockIndex] |= toBlockMask
	}
}

// AddRange adds the given port range to the set.
func (s *PortSet) AddRange(from, to uint16) {
	fromPort := uint(from)
	toPort := uint(to)
	panicOnZeroPort(fromPort)
	if fromPort >= toPort {
		panic(fmt.Sprintf("invalid port range: %d >= %d", fromPort, toPort))
	}
	toPort++ // Make toPort exclusive.
	s.addRange(fromPort, toPort)
}

// Parse parses the given string as a comma-separated list of ports and port ranges,
// and adds them to the set on success, or returns an error.
func (s *PortSet) Parse(portSetString string) error {
	for len(portSetString) > 0 {
		var portRangeString string

		commaIndex := strings.IndexByte(portSetString, ',')
		if commaIndex == -1 {
			portRangeString = portSetString
			portSetString = ""
		} else {
			portRangeString = portSetString[:commaIndex]
			portSetString = portSetString[commaIndex+1:]
		}

		dashIndex := strings.IndexByte(portRangeString, '-')
		if dashIndex == -1 {
			port, err := strconv.ParseUint(portRangeString, 10, 16)
			if err != nil {
				return fmt.Errorf("invalid port %q: %w", portRangeString, err)
			}
			if port == 0 {
				return fmt.Errorf("invalid port %q: %w", portRangeString, ErrZeroPort)
			}
			s.add(uint(port))
		} else {
			fromPort, err := strconv.ParseUint(portRangeString[:dashIndex], 10, 16)
			if err != nil {
				return fmt.Errorf("invalid port range %q: %w", portRangeString, err)
			}
			if fromPort == 0 {
				return fmt.Errorf("invalid port range %q: %w", portRangeString, ErrZeroPort)
			}
			toPort, err := strconv.ParseUint(portRangeString[dashIndex+1:], 10, 16)
			if err != nil {
				return fmt.Errorf("invalid port range %q: %w", portRangeString, err)
			}
			if fromPort >= toPort {
				return fmt.Errorf("invalid port range %q: %d >= %d", portRangeString, fromPort, toPort)
			}
			toPort++ // Make toPort exclusive.
			s.addRange(uint(fromPort), uint(toPort))
		}
	}
	return nil
}

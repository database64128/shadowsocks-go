package prefixset

import (
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/bytestrings"
	"github.com/database64128/shadowsocks-go/mmap"
	"go4.org/netipx"
)

// Config is the configuration for a prefix set.
type Config struct {
	// Name is the name of the prefix set.
	Name string `json:"name"`

	// Path is the path to the prefix set file.
	Path string `json:"path"`
}

// IPSet creates a prefix set from the configuration.
func (psc Config) IPSet() (*netipx.IPSet, error) {
	data, close, err := mmap.ReadFile[string](psc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read prefix set file: %w", err)
	}
	defer close()

	return IPSetFromText(data)
}

// IPSetFromText parses prefixes from the text and builds a prefix set.
func IPSetFromText(text string) (*netipx.IPSet, error) {
	var sb netipx.IPSetBuilder

	for line := range bytestrings.NonEmptyLines(text) {
		if line[0] == '#' {
			continue
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, err
		}

		sb.AddPrefix(prefix)
	}

	return sb.IPSet()
}

// IPSetToText returns the text representation of the prefix set.
func IPSetToText(s *netipx.IPSet) []byte {
	prefixes := s.Prefixes()
	b := make([]byte, 0, 20*len(prefixes))
	for _, prefix := range prefixes {
		b = prefix.AppendTo(b)
		b = append(b, '\n')
	}
	return b
}

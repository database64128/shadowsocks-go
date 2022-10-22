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
	Name string `json:"name"`
	Path string `json:"path"`
}

// IPSet creates a prefix set from the configuration.
func (psc Config) IPSet() (*netipx.IPSet, error) {
	data, err := mmap.ReadFile[string](psc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to load prefix set %s: %w", psc.Name, err)
	}
	defer mmap.Unmap(data)

	return IPSetFromText(data)
}

// IPSetFromText parses prefixes from the text and builds a prefix set.
func IPSetFromText(text string) (*netipx.IPSet, error) {
	var (
		line string
		sb   netipx.IPSetBuilder
	)

	for {
		line, text = bytestrings.NextNonEmptyLine(text)
		if len(line) == 0 {
			break
		}

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

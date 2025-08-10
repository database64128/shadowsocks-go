package prefixset

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"

	"github.com/database64128/shadowsocks-go/bytestrings"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/gaissmai/bart"
)

// Config is the configuration for a prefix set.
type Config struct {
	// Name is the name of the prefix set.
	Name string `json:"name"`

	// Path is the path to the prefix set file.
	Path string `json:"path"`
}

// LoadPrefixSet loads the prefix set from the file.
func (psc Config) LoadPrefixSet() (*bart.Lite, error) {
	data, close, err := mmap.ReadFile[string](psc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read prefix set file: %w", err)
	}
	defer close()

	return PrefixSetFromText(data)
}

// PrefixSetFromText parses prefixes from the text and builds a prefix set.
func PrefixSetFromText(text string) (*bart.Lite, error) {
	var s bart.Lite

	for line := range bytestrings.NonEmptyLines(text) {
		if line[0] == '#' {
			continue
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, err
		}

		s.Insert(prefix)
	}

	return &s, nil
}

// PrefixSetToText returns the text representation of the prefix set.
func PrefixSetToText(s *bart.Lite) []byte {
	const (
		prefix4LineLen = len("255.255.255.255/32\n")
		prefix6LineLen = len("ffff:ffff:ffff:ffff::/64\n")
	)
	b := make([]byte, 0, prefix4LineLen*s.Size4()+prefix6LineLen*s.Size6())
	for prefix := range s.All() {
		b = prefix.AppendTo(b)
		b = append(b, '\n')
	}
	return b
}

// PrefixSetWriteText writes the prefix set to the given writer in text format.
func PrefixSetWriteText(s *bart.Lite, w io.Writer) error {
	const maxLineLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128\n")
	b := make([]byte, 0, maxLineLen)
	bw := bufio.NewWriterSize(w, 128*1024)

	for prefix := range s.All() {
		// When the buffered writer is nearly full, use a small temporary buffer
		// instead of flushing the writer. This ensures that writes to the
		// underlying writer are page-aligned.
		line := b
		if bw.Available() >= maxLineLen {
			line = bw.AvailableBuffer()
		}

		line = prefix.AppendTo(line)
		line = append(line, '\n')

		if _, err := bw.Write(line); err != nil {
			return err
		}
	}

	return bw.Flush()
}

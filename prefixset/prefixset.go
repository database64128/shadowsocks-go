// Package prefixset implements serialization and deserialization of IP prefix sets.
//
// # File Formats
//
// A prefix set can be stored in either text or binary format.
// The text format is human-readable and can be edited with a text editor,
// while the binary format is more compact and efficient for programmatic use.
//
// # Text
//
// The text format is a simple line-based format where each line contains a single IP prefix
// in CIDR notation. Lines starting with '#' are treated as comments and ignored. Empty lines
// are also ignored.
//
// Example:
//
//	# IPv6 private address space
//	::/128
//	::1/128
//	fc00::/7
//	fe80::/10
//	ff00::/8
//
// # Binary
//
// The binary format is a compact representation of the prefix set. It consists of a header
// followed by a sequence of serialized prefixes.
//
// # Header
//
//	+---------------------------+-------------------+-------------------+
//	|       Magic Number        | IPv4 Prefix Count | IPv6 Prefix Count |
//	+---------------------------+-------------------+-------------------+
//	| 0x99d3d386ace0cae1: u64be |       u64be       |       u64be       |
//	+---------------------------+-------------------+-------------------+
//
// The magic number is generated with:
//
//	author := binary.BigEndian.Uint64([]byte("Ian Chen"))
//	prefixes := binary.BigEndian.Uint64([]byte("Prefixes"))
//	fmt.Printf("%#x\n", author+prefixes)
//
// # Prefix Serialization
//
// Each prefix is serialized as follows:
//
//	+----------------------+---------------+
//	| Prefix Length (bits) | Address Bytes |
//	+----------------------+---------------+
//	|          u8          |     []byte    |
//	+----------------------+---------------+
//
// For IPv4 prefixes, the prefix length is stored as the actual prefix length plus 192.
//
// The address bytes are stored in network byte order (big-endian), up to the prefix length.
//
//   - IPv6 prefix length: [0, 128]
//   - IPv4 prefix length: [192, 224] (actual prefix length + 192)
//   - Address bytes length = (bits + 7) / 8
package prefixset

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/database64128/shadowsocks-go/bytestrings"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/gaissmai/bart"
)

// Config is the configuration for a prefix set.
type Config struct {
	// Name is the name of the prefix set.
	Name string `json:"name"`

	// Type is the type of the prefix set.
	//
	//  - "text": text format (default)
	//  - "binary": binary format
	//
	// See the package documentation for details on the file formats.
	Type string `json:"type,omitzero"`

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

	switch psc.Type {
	case "text", "":
		return PrefixSetFromText(data)
	case "binary":
		var s bart.Lite
		if err := UnmarshalReadBinary(strings.NewReader(data), &s); err != nil {
			return nil, err
		}
		return &s, nil
	default:
		return nil, fmt.Errorf("unknown prefix set type: %q", psc.Type)
	}
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
			// As of Go 1.27, [netip.ParsePrefix] escapes the input string by using
			// an unexported error type that embeds the input string directly. When
			// our input string is from an mmapped file, the returned error will
			// become invalid when we unmap the file.
			//
			// Because of the escaping, we can't pass a stack copy of the string.
			// And because the error type is unexported, we can't change the string
			// embedded in the returned error. What we can do here, is to get the
			// error string and wrap it in a new error.
			return nil, errors.New(err.Error())
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

const (
	binaryBigEndianAuthor   = 0x49616e204368656e                              // binary.BigEndian.Uint64([]byte("Ian Chen"))
	binaryBigEndianPrefixes = 0x5072656669786573                              // binary.BigEndian.Uint64([]byte("Prefixes"))
	binaryBigEndianMagic    = binaryBigEndianAuthor + binaryBigEndianPrefixes // 0x99d3d386ace0cae1
)

// MarshalWriteBinary serializes the prefix set to w in binary format.
func MarshalWriteBinary(w io.Writer, s *bart.Lite) error {
	bw, ok := w.(interface {
		io.Writer
		io.ByteWriter
	})
	if !ok {
		bw = bufio.NewWriterSize(w, 128*1024)
	}

	b := make([]byte, 24)
	binary.BigEndian.PutUint64(b, binaryBigEndianMagic)
	binary.BigEndian.PutUint64(b[8:], uint64(s.Size4()))
	binary.BigEndian.PutUint64(b[16:], uint64(s.Size6()))
	if _, err := bw.Write(b); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for prefix := range s.All() {
		ip := prefix.Addr()
		bits := byte(prefix.Bits())
		addrLen := (bits + 7) / 8
		if ip.Is4() {
			bits += 192
		}

		if err := bw.WriteByte(bits); err != nil {
			return fmt.Errorf("failed to write prefix length: %w", err)
		}

		b, err := ip.AppendBinary(b[:0])
		if err != nil {
			return fmt.Errorf("failed to append address bytes: %w", err)
		}
		if int(addrLen) > len(b) {
			return fmt.Errorf("invalid prefix: %s", prefix)
		}
		if _, err := bw.Write(b[:addrLen]); err != nil {
			return fmt.Errorf("failed to write address bytes: %w", err)
		}
	}

	return nil
}

// UnmarshalReadBinary deserializes a prefix set from r in binary format.
func UnmarshalReadBinary(r io.Reader, s *bart.Lite) error {
	br, ok := r.(interface {
		io.Reader
		io.ByteReader
	})
	if !ok {
		br = bufio.NewReaderSize(r, 128*1024)
	}

	b := make([]byte, 24)
	if _, err := io.ReadFull(br, b); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	if magic := binary.BigEndian.Uint64(b); magic != binaryBigEndianMagic {
		return fmt.Errorf("invalid magic number: %#x", magic)
	}
	count4 := binary.BigEndian.Uint64(b[8:])
	count6 := binary.BigEndian.Uint64(b[16:])

	for {
		bits, err := br.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read prefix length: %w", err)
		}

		*(*[16]byte)(b) = [16]byte{}

		var ip netip.Addr
		if bits <= 128 {
			addrLen := (bits + 7) / 8
			if _, err := io.ReadFull(br, b[:addrLen]); err != nil {
				return fmt.Errorf("failed to read IPv6 address bytes: %w", err)
			}
			ip = netip.AddrFrom16([16]byte(b))
		} else {
			bits -= 192
			// As of Go 1.27, checking bits > 32 does not eliminate the bounds check on b[:addrLen],
			// probably because the compiler gets confused by the potential underflow in bits -= 192.
			// So we check addrLen > 4 instead.
			addrLen := (bits + 7) / 8
			if addrLen > 4 {
				return fmt.Errorf("invalid prefix length: %d", bits)
			}
			if _, err := io.ReadFull(br, b[:addrLen]); err != nil {
				return fmt.Errorf("failed to read IPv4 address bytes: %w", err)
			}
			ip = netip.AddrFrom4([4]byte(b))
		}

		prefix := netip.PrefixFrom(ip, int(bits))
		s.Insert(prefix)
	}

	if size4 := s.Size4(); uint64(size4) != count4 {
		return fmt.Errorf("IPv4 prefix count mismatch: actual %d != header %d", size4, count4)
	}
	if size6 := s.Size6(); uint64(size6) != count6 {
		return fmt.Errorf("IPv6 prefix count mismatch: actual %d != header %d", size6, count6)
	}

	return nil
}

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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"unsafe"

	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/gaissmai/bart"
)

// Config is the configuration for a prefix set.
type Config struct {
	// Name is the name of the prefix set.
	Name string `json:"name"`

	// Type specifies the file format.
	//
	//  - "text": text format (default)
	//  - "binary": binary format
	//
	// See the package documentation for details on the file formats.
	Type string `json:"type,omitzero"`

	// Path is the path to the prefix set file.
	Path string `json:"path"`

	// Loader specifies the IO backend to use for loading the prefix set file.
	//
	//  - "bufio": buffered IO (default)
	//  - "mmap": memory-mapped IO
	Loader string `json:"loader,omitzero"`
}

// LoadPrefixSet loads the prefix set from the file.
func (cfg Config) LoadPrefixSet() (*PrefixSet, error) {
	var (
		unmarshalRead func(io.Reader, *bart.Lite) error
		unmarshal     func(string, *bart.Lite) error
	)
	switch cfg.Type {
	case "text", "":
		unmarshalRead = UnmarshalReadText
		unmarshal = UnmarshalText
	case "binary":
		unmarshalRead = UnmarshalReadBinary
		unmarshal = func(data string, s *bart.Lite) error {
			return UnmarshalReadBinary(strings.NewReader(data), s)
		}
	default:
		return nil, fmt.Errorf("unknown file type: %q", cfg.Type)
	}

	var s PrefixSet
	switch cfg.Loader {
	case "bufio", "":
		f, err := os.Open(cfg.Path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if err := unmarshalRead(f, &s.Lite); err != nil {
			return nil, err
		}

	case "mmap":
		data, close, err := mmap.ReadFile[string](cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read prefix set file: %w", err)
		}
		defer close()

		if err := unmarshal(data, &s.Lite); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid loader: %q", cfg.Loader)
	}
	return &s, nil
}

// FromPrefixesAndPrefixSetNames returns a prefix set assembled from
// the given prefixes and the named prefix sets.
func FromPrefixesAndPrefixSetNames(
	prefixes []netip.Prefix,
	names []string,
	prefixSetByName map[string]*PrefixSet,
) (*PrefixSet, error) {
	if len(prefixes) == 0 && len(names) == 1 {
		s, ok := prefixSetByName[names[0]]
		if !ok {
			return nil, fmt.Errorf("prefix set not found: %q", names[0])
		}
		return s, nil
	}

	var s PrefixSet

	for _, prefix := range prefixes {
		s.Insert(prefix)
	}

	for _, name := range names {
		o, ok := prefixSetByName[name]
		if !ok {
			return nil, fmt.Errorf("prefix set not found: %q", name)
		}
		s.Union(&o.Lite)
	}

	return &s, nil
}

// PrefixSet is an IP address prefix set.
type PrefixSet struct {
	bart.Lite
}

// Contains calls [bart.Lite.Contains] with ip unmapped and any zone identifier stripped.
func (s *PrefixSet) Contains(ip netip.Addr) bool {
	// Another day, another rabbit hole, oh well...
	//
	// As of Go 1.27, the official way to write this would be:
	//
	//	ip = ip.Unmap().WithZone("")
	//
	// So why not? Well, Unmap is inlineable, but WithZone is not.
	// We don't want to impose the cost of a function call on all IPs.
	// Is there a way out of this? Yes! We can do something like:
	//
	//	if ip.Is6() {
	//		ip = ip.Unmap()
	//		if ip.Zone() != "" {
	//			ip = ip.WithZone("")
	//		}
	//	}
	//
	// Because Zone can be inlined, we only pay the function call cost
	// when the IP actually contains a zone. But can we do better?
	//
	// Turns out there's an unexported netip.Addr.withoutZone that does
	// exactly what we want. Unfortunately, getting it exported is not
	// a battle we can win. So there really is no way for us to use
	// withoutZone, right?
	//
	// Actually, there is a way... netip.PrefixFrom calls withoutZone,
	// and it's inlineable. With this careful setup below, we are able
	// to get the compiler to generate the exact same machine code as if
	// we were doing:
	//
	//	ip = ip.withoutZone().Unmap()
	//
	// Mission accomplished, with the purest Go magic!
	//
	// Update: As of https://github.com/gaissmai/bart/pull/430,
	// IPv6 zone stripping is now handled internally by bart.
	// The original comment is preserved for historical context.
	return s.Lite.Contains(ip.Unmap())
}

// TextLineError represents a text format deserialization error.
type TextLineError struct {
	Line int
	Err  error
}

func (e TextLineError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e TextLineError) Unwrap() error {
	return e.Err
}

var (
	ErrInvalidPrefix = errors.New("invalid prefix")
	ErrLineTooLong   = errors.New("line too long")
)

// As of Go 1.27, [netip.ParsePrefix] escapes the input string by using
// an unexported error type that embeds the input string directly. When
// our input string is from an mmapped file, the returned error will
// become invalid when we unmap the file.
//
// Because of the escaping, we can't pass a stack copy of the string.
// And because the error type is unexported, we can't change the string
// embedded in the returned error. What we can do here, is to get the
// error string and wrap it in a new error.
func fixNetipParseError(err error) error {
	return fmt.Errorf("%w: %s", ErrInvalidPrefix, err.Error())
}

// maxUnmarshalLineLen is the maximum line length permitted by [UnmarshalText] and [UnmarshalReadText].
// It intentionally includes some extra headroom to give users better error messages for prefixes with zones.
const maxUnmarshalLineLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%AnImpossiblyLongZone/128")

// UnmarshalText parses prefixes from the text and builds a prefix set.
func UnmarshalText(text string, s *bart.Lite) error {
	if s == nil {
		panic("prefixset.UnmarshalText: prefix set is nil")
	}

	var lineNum int
	for line := range strings.Lines(text) {
		lineNum++
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if len(line) > maxUnmarshalLineLen {
			return TextLineError{Line: lineNum, Err: ErrLineTooLong}
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return TextLineError{Line: lineNum, Err: fixNetipParseError(err)}
		}
		s.Insert(prefix)
	}

	return nil
}

// MarshalText returns the text representation of the prefix set.
func MarshalText(s *bart.Lite) []byte {
	const (
		prefix4LineLen = len("255.255.255.255/32\n")
		prefix6LineLen = len("ffff:ffff:ffff:ffff::/64\n")
	)
	b := make([]byte, 0, prefix4LineLen*s.Size4()+prefix6LineLen*s.Size6())
	return AppendText(b, s)
}

// AppendText appends the prefix set serialized in text format to b and returns the updated slice.
func AppendText(b []byte, s *bart.Lite) []byte {
	for prefix := range s.All() {
		b = prefix.AppendTo(b)
		b = append(b, '\n')
	}
	return b
}

// MarshalWriteText serializes the prefix set to w in text format.
func MarshalWriteText(w io.Writer, s *bart.Lite) (err error) {
	bw, ok := w.(interface {
		io.Writer
		io.ByteWriter
		Available() int
		AvailableBuffer() []byte
	})
	if !ok {
		b := bufio.NewWriterSize(w, defaultBufferSize)
		defer func() {
			if flushErr := b.Flush(); flushErr != nil && err == nil {
				err = flushErr
			}
		}()
		bw = b
	}

	const maxLineLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128\n")
	b := make([]byte, 0, maxLineLen)

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

	return nil
}

// UnmarshalReadText deserializes a prefix set from r in text format.
func UnmarshalReadText(r io.Reader, s *bart.Lite) error {
	if s == nil {
		panic("prefixset.UnmarshalReadText: prefix set is nil")
	}

	var b []byte
	br := newLineReader(r)

	for lineNum := 1; ; lineNum++ {
		dst, line, err := br.ReadLine(b)
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] != '#' {
			if len(line) > maxUnmarshalLineLen {
				return TextLineError{Line: lineNum, Err: ErrLineTooLong}
			}

			prefix, err := netip.ParsePrefix(unsafe.String(unsafe.SliceData(line), len(line)))
			if err != nil {
				return TextLineError{Line: lineNum, Err: fixNetipParseError(err)}
			}
			s.Insert(prefix)
		}
		if err != nil {
			switch err {
			case io.EOF:
				return nil
			case io.ErrShortBuffer:
				return TextLineError{Line: lineNum, Err: ErrLineTooLong}
			default:
				return TextLineError{Line: lineNum, Err: err}
			}
		}
		b = dst[:0]
	}
}

// lineReader provides efficient read access to newline-delimited text.
//
// Unlike [bufio.Reader.ReadLine] and [bufio.Scanner], lineReader guarantees
// that all reads from the underlying reader are page-aligned.
type lineReader struct {
	buf   []byte
	r, w  int
	err   error
	inner io.Reader
}

func newLineReader(r io.Reader) *lineReader {
	bufSize := readBufferSize(r)
	if bufSize < defaultBufferSize {
		// An extra byte allows us to discover EOF without
		// copying the no-LF trailing line to dst.
		bufSize++
	}
	return &lineReader{
		buf:   make([]byte, bufSize),
		inner: r,
	}
}

// ReadLine returns the updated dst buffer, the next line with the trailing
// '\n' or '\r\n' bytes removed, and any error encountered.
//
// The returned line references either dst or the internal buffer.
//
// Callers must first process the returned line before checking the error.
func (lr *lineReader) ReadLine(dst []byte) ([]byte, []byte, error) {
	for searchStart := 0; ; {
		b := lr.buf[lr.r:lr.w]

		if len(b) > searchStart {
			if i := bytes.IndexByte(b[searchStart:], '\n'); i >= 0 {
				i += searchStart
				lr.r += i + 1
				line := b[:i] // without '\n'
				dst, line = concatLine(dst, line)
				return dst, line, nil
			}
		}

		if lr.err != nil {
			lr.r = lr.w
			dst, b = concatLine(dst, b)
			return dst, b, lr.err
		}

		switch lr.w {
		case lr.r:
			if lr.r != 0 {
				lr.r, lr.w = 0, 0
			}
		case len(lr.buf):
			if lr.r != 0 {
				dst = append(dst, b...)
				lr.r, lr.w = 0, 0
			} else {
				// Line is longer than buf.
				return dst, nil, io.ErrShortBuffer
			}
		}

		searchStart = lr.w - lr.r
		n, err := lr.inner.Read(lr.buf[lr.w:])
		lr.w += n
		lr.err = err
	}
}

func concatLine(dst, line []byte) ([]byte, []byte) {
	if len(dst) > 0 {
		dst = append(dst, line...)
		line = dst
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return dst, line
}

const (
	binaryBigEndianAuthor   = 0x49616e204368656e                              // binary.BigEndian.Uint64([]byte("Ian Chen"))
	binaryBigEndianPrefixes = 0x5072656669786573                              // binary.BigEndian.Uint64([]byte("Prefixes"))
	binaryBigEndianMagic    = binaryBigEndianAuthor + binaryBigEndianPrefixes // 0x99d3d386ace0cae1
)

// MarshalWriteBinary serializes the prefix set to w in binary format.
func MarshalWriteBinary(w io.Writer, s *bart.Lite) (err error) {
	bw, ok := w.(interface {
		io.Writer
		io.ByteWriter
	})
	if !ok {
		b := bufio.NewWriterSize(w, defaultBufferSize)
		defer func() {
			if flushErr := b.Flush(); flushErr != nil && err == nil {
				err = flushErr
			}
		}()
		bw = b
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
	if s == nil {
		panic("prefixset.UnmarshalReadBinary: prefix set is nil")
	}

	br, ok := r.(interface {
		io.Reader
		io.ByteReader
	})
	if !ok {
		br = bufio.NewReaderSize(r, readBufferSize(r))
	}

	b := make([]byte, 24)
	if _, err := io.ReadFull(br, b); err != nil {
		return fmt.Errorf("failed to read header: %w", toUnexpectedEOF(err))
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
				return fmt.Errorf("failed to read IPv6 address bytes: %w", toUnexpectedEOF(err))
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
				return fmt.Errorf("failed to read IPv4 address bytes: %w", toUnexpectedEOF(err))
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

const defaultBufferSize = 128 * 1024

func readBufferSize(r io.Reader) int {
	if f, ok := r.(fs.File); ok {
		if fi, err := f.Stat(); err == nil {
			if size := fi.Size(); size > 0 {
				return int(min(size, defaultBufferSize))
			}
		}
	}
	return defaultBufferSize
}

// toUnexpectedEOF converts [io.EOF] to [io.ErrUnexpectedEOF].
func toUnexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

package bytestrings

import (
	"iter"
	"strings"
	"unsafe"
)

// NextNonEmptyLine returns the next non-empty line and the remaining text.
// The line has its line feed ('\n') and carriage return ('\r') characters removed.
func NextNonEmptyLine[T ~[]byte | ~string](text T) (T, T) {
	for {
		lfIndex := strings.IndexByte(*(*string)(unsafe.Pointer(&text)), '\n')
		if lfIndex == -1 {
			return text, text[len(text):]
		}
		line := text[:lfIndex]
		text = text[lfIndex+1:]
		if lfIndex == 0 {
			continue
		}
		if line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			continue
		}
		return line, text
	}
}

// NonEmptyLines returns an iterator over the non-empty lines in the text,
// with line feed ('\n') and carriage return ('\r') characters removed.
func NonEmptyLines[T ~[]byte | ~string](text T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for lfIndex := 0; len(text) > 0; text = text[lfIndex+1:] {
			lfIndex = strings.IndexByte(*(*string)(unsafe.Pointer(&text)), '\n')
			switch lfIndex {
			case -1:
				_ = yield(text)
				return
			case 0:
				continue
			}

			line := text[:lfIndex]
			if line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if len(line) == 0 {
				continue
			}
			if !yield(line) {
				return
			}
		}
	}
}

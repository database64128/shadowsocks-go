package bytestrings

import (
	"strings"
	"unsafe"
)

// NextNonEmptyLine returns the next non-empty line and the remaining text.
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

package jsoncfg

import (
	"io/fs"
	"strconv"
)

// FileMode represents [fs.FileMode] as an octal number in a string.
type FileMode fs.FileMode

// Value returns the file mode as [fs.FileMode].
func (m FileMode) Value() fs.FileMode {
	return fs.FileMode(m)
}

// AppendText implements [encoding.TextAppender].
func (m FileMode) AppendText(b []byte) ([]byte, error) {
	return strconv.AppendUint(b, uint64(m), 8), nil
}

// MarshalText implements [encoding.TextMarshaler].
func (m FileMode) MarshalText() ([]byte, error) {
	return m.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (m *FileMode) UnmarshalText(text []byte) error {
	mode, err := strconv.ParseUint(string(text), 8, 32)
	if err != nil {
		return err
	}
	*m = FileMode(mode)
	return nil
}

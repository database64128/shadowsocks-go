//go:build unix || windows

package mmap

import "os"

// ReadFile maps the named file into memory for reading.
func ReadFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fs, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fs.Size()
	if size == 0 {
		return nil, nil
	}

	return readFile(f, size)
}

//go:build !unix && !windows

package mmap

import "os"

// ReadFile maps the named file into memory for reading.
func ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// Unmap removes the memory mapping.
func Unmap(b []byte) error {
	return nil
}

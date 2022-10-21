//go:build !unix && !windows

package mmap

import (
	"os"
	"unsafe"
)

// ReadFile maps the named file into memory for reading.
func ReadFile[T ~[]byte | ~string](name string) (data T, err error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return
	}
	return *(*T)(unsafe.Pointer(&b)), nil
}

// Unmap removes the memory mapping.
func Unmap[T ~[]byte | ~string](b T) error {
	return nil
}

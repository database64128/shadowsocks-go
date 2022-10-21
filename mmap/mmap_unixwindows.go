//go:build unix || windows

package mmap

import (
	"os"
	"unsafe"
)

// ReadFile maps the named file into memory for reading.
func ReadFile[T ~[]byte | ~string](name string) (data T, err error) {
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()

	fs, err := f.Stat()
	if err != nil {
		return
	}

	size := fs.Size()
	if size == 0 {
		return
	}

	addr, err := readFile(f, size)
	if err != nil {
		return
	}

	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return *(*T)(unsafe.Pointer(&b)), nil
}

// Unmap removes the memory mapping.
func Unmap[T ~[]byte | ~string](data T) error {
	if len(data) == 0 {
		return nil
	}
	return unmap(*(*uintptr)(unsafe.Pointer(&data)), len(data))
}

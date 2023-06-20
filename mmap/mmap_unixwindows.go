//go:build unix || windows

package mmap

import (
	"os"
	"unsafe"
)

type sliceHeader struct {
	data uintptr
	len  int
	cap  int
}

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

	b := sliceHeader{
		data: addr,
		len:  int(size),
		cap:  int(size),
	}
	return *(*T)(unsafe.Pointer(&b)), nil
}

// Unmap removes the memory mapping.
func Unmap[T ~[]byte | ~string](data T) error {
	if len(data) == 0 {
		return nil
	}
	return unmap(*(*uintptr)(unsafe.Pointer(&data)), len(data))
}

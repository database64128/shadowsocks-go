package mmap

import (
	"errors"
	"io"
	"os"
	"unsafe"
)

// ReadFile maps the named file into memory for reading.
// On success, it returns the mapped data as a byte slice or a string,
// and a function that unmaps the data.
func ReadFile[T ~[]byte | ~string](name string) (data T, close func() error, err error) {
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

	addr, close, err := readFile(f, uintptr(size))
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return readFileFallback[T](f, size)
		}
		return
	}

	b := unsafe.Slice((*byte)(addr), size)
	return *(*T)(unsafe.Pointer(&b)), close, nil
}

func readFileFallback[T ~[]byte | ~string](f *os.File, size int64) (data T, close func() error, err error) {
	b := make([]byte, size)
	if _, err = io.ReadFull(f, b); err != nil {
		return
	}
	return *(*T)(unsafe.Pointer(&b)), func() error { return nil }, nil
}

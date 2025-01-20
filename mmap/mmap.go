package mmap

import (
	"errors"
	"io"
	"os"
	"unsafe"
)

var ErrFileTooLarge = errors.New("file too large")

// ReadFile maps the named file into memory for reading.
// On success, it returns the mapped data as a byte slice or a string,
// and a function that unmaps the data.
func ReadFile[T ~[]byte | ~string](name string) (data T, close func() error, err error) {
	f, err := os.Open(name)
	if err != nil {
		return data, nil, err
	}
	defer f.Close()

	fs, err := f.Stat()
	if err != nil {
		return data, nil, err
	}

	size64 := fs.Size()
	if size64 == 0 {
		return data, func() error { return nil }, nil
	}

	size := int(size64)
	if int64(size) != size64 {
		return data, nil, ErrFileTooLarge
	}

	addr, close, err := readFile(f, uintptr(size))
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return readFileFallback[T](f, size)
		}
		return data, nil, err
	}

	b := unsafe.Slice((*byte)(addr), size)
	return *(*T)(unsafe.Pointer(&b)), close, nil
}

func readFileFallback[T ~[]byte | ~string](f *os.File, size int) (data T, close func() error, err error) {
	b := make([]byte, size)
	if _, err = io.ReadFull(f, b); err != nil {
		return data, nil, err
	}
	return *(*T)(unsafe.Pointer(&b)), func() error { return nil }, nil
}

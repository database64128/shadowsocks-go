//go:build !unix && !windows

package mmap

import (
	"errors"
	"os"
	"unsafe"
)

type mmapUnsupportedError struct{}

func (mmapUnsupportedError) Error() string {
	return "mmap is not supported on this platform"
}

func (mmapUnsupportedError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

func readFile(_ *os.File, _ uintptr) (addr unsafe.Pointer, close func() error, err error) {
	return nil, nil, mmapUnsupportedError{}
}

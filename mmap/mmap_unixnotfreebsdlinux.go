//go:build unix && !freebsd && !linux

package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readFile(f *os.File, size int64) (uintptr, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	return *(*uintptr)(unsafe.Pointer(&data)), nil
}

func unmap(addr uintptr, length int) error {
	return unix.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(addr)), length))
}

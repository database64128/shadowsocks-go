//go:build unix && ((!freebsd && !linux) || (!amd64 && !arm64 && !loong64 && !mips64 && !mips64le && !ppc64 && !ppc64le && !riscv64 && !sparc64))

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
	b := sliceHeader{
		data: addr,
		len:  length,
		cap:  length,
	}
	return unix.Munmap(*(*[]byte)(unsafe.Pointer(&b)))
}

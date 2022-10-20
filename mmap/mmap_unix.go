//go:build unix

package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readFile(f *os.File, size int64) ([]byte, error) {
	r0, _, e1 := unix.Syscall6(unix.SYS_MMAP, 0, uintptr(size), unix.PROT_READ, unix.MAP_SHARED, f.Fd(), 0)
	if e1 != 0 {
		return nil, os.NewSyscallError("mmap", e1)
	}

	return unsafe.Slice((*byte)(unsafe.Pointer(r0)), size), nil
}

// Unmap removes the memory mapping.
func Unmap(b []byte) error {
	_, _, e1 := unix.Syscall(unix.SYS_MUNMAP, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if e1 != 0 {
		return os.NewSyscallError("munmap", e1)
	}
	return nil
}

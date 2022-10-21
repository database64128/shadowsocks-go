//go:build unix

package mmap

import (
	"os"

	"golang.org/x/sys/unix"
)

func readFile(f *os.File, size int64) (uintptr, error) {
	r0, _, e1 := unix.Syscall6(unix.SYS_MMAP, 0, uintptr(size), unix.PROT_READ, unix.MAP_SHARED, f.Fd(), 0)
	if e1 != 0 {
		return 0, os.NewSyscallError("mmap", e1)
	}
	return r0, nil
}

func unmap(addr uintptr, length int) error {
	_, _, e1 := unix.Syscall(unix.SYS_MUNMAP, addr, uintptr(length), 0)
	if e1 != 0 {
		return os.NewSyscallError("munmap", e1)
	}
	return nil
}

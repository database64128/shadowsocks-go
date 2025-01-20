//go:build unix

package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readFile(f *os.File, size uintptr) (addr unsafe.Pointer, close func() error, err error) {
	rawConn, err := f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}

	if cerr := rawConn.Control(func(fd uintptr) {
		addr, err = unix.MmapPtr(int(fd), 0, nil, size, unix.PROT_READ, unix.MAP_SHARED)
	}); cerr != nil {
		return nil, nil, cerr
	}

	if err != nil {
		return nil, nil, os.NewSyscallError("mmap", err)
	}

	return addr, func() error {
		if err := unix.MunmapPtr(addr, size); err != nil {
			return os.NewSyscallError("munmap", err)
		}
		return nil
	}, nil
}

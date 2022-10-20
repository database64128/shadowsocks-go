package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readFile(f *os.File, size int64) ([]byte, error) {
	handle, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, os.NewSyscallError("CreateFileMappingW", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, os.NewSyscallError("MapViewOfFile", err)
	}

	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size), nil
}

// Unmap removes the memory mapping.
func Unmap(b []byte) error {
	return windows.UnmapViewOfFile(uintptr(unsafe.Pointer(&b[0])))
}

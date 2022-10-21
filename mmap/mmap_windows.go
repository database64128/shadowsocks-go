package mmap

import (
	"os"

	"golang.org/x/sys/windows"
)

func readFile(f *os.File, size int64) (uintptr, error) {
	handle, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return 0, os.NewSyscallError("CreateFileMappingW", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return 0, os.NewSyscallError("MapViewOfFile", err)
	}
	return addr, nil
}

func unmap(addr uintptr, length int) error {
	return windows.UnmapViewOfFile(addr)
}

package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readFile(f *os.File, _ uintptr) (addr unsafe.Pointer, close func() error, err error) {
	handle, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, nil, os.NewSyscallError("CreateFileMappingW", err)
	}
	defer windows.CloseHandle(handle)

	addrUintptr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, nil, os.NewSyscallError("MapViewOfFile", err)
	}
	return *(*unsafe.Pointer)(unsafe.Pointer(&addrUintptr)), // workaround for unsafeptr check in go vet, see https://github.com/golang/go/issues/58625
		func() error {
			return windows.UnmapViewOfFile(addrUintptr)
		}, nil
}

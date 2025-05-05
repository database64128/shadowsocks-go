package mmap

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readFile(f *os.File, size uintptr) (addr unsafe.Pointer, close func() error, err error) {
	rawConn, err := f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}

	var handle windows.Handle

	if cerr := rawConn.Control(func(fd uintptr) {
		handle, err = windows.CreateFileMapping(windows.Handle(fd), nil, windows.PAGE_READONLY, 0, 0, nil)
	}); cerr != nil {
		return nil, nil, cerr
	}

	if err != nil {
		return nil, nil, os.NewSyscallError("CreateFileMappingW", err)
	}
	defer windows.CloseHandle(handle)

	addrUintptr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, nil, os.NewSyscallError("MapViewOfFile", err)
	}

	var info windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addrUintptr, &info, unsafe.Sizeof(info)); err != nil {
		_ = windows.UnmapViewOfFile(addrUintptr)
		return nil, nil, os.NewSyscallError("VirtualQuery", err)
	}
	if info.RegionSize < size {
		_ = windows.UnmapViewOfFile(addrUintptr)
		return nil, nil, ErrFileTooLarge
	}

	return *(*unsafe.Pointer)(unsafe.Pointer(&addrUintptr)), // workaround for unsafeptr check in go vet, see https://github.com/golang/go/issues/58625
		func() error {
			if err := windows.UnmapViewOfFile(addrUintptr); err != nil {
				return os.NewSyscallError("UnmapViewOfFile", err)
			}
			return nil
		}, nil
}

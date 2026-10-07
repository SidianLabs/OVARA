//go:build windows

package flock

import (
	"os"

	"golang.org/x/sys/windows"
)

// The whole file is locked: offset 0, length 2^64-1.
const lockAll = ^uint32(0)

func lock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, lockAll, lockAll, ol)
}

func unlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockAll, lockAll, ol)
}

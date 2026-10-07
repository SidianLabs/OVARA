// Package flock provides an exclusive advisory file lock that works on
// both Unix (flock(2)) and Windows (LockFileEx). The authority journals
// serialize multi-process access with it; syscall.Flock alone does not
// exist on Windows, which previously made the whole gateway fail to build
// there.
package flock

import "os"

// Lock blocks until it holds an exclusive lock on f.
func Lock(f *os.File) error { return lock(f) }

// Unlock releases a lock taken with Lock.
func Unlock(f *os.File) error { return unlock(f) }

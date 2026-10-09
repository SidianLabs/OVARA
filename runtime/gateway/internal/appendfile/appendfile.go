// Package appendfile holds helpers for files opened with O_APPEND.
//
// On Windows, Go opens an O_APPEND file with FILE_APPEND_DATA access but
// without FILE_WRITE_DATA, so (*os.File).Truncate on that handle fails
// with "Access is denied". Truncate works around that by truncating
// through a second, non-append handle on Windows; on Unix it truncates
// the given handle directly, exactly as before.
//
// A second handle can truncate even while the original handle holds a
// flock (LockFileEx) on the whole file, so callers keep their locking.
package appendfile

import "os"

// Truncate changes the size of f, which may have been opened O_APPEND.
func Truncate(f *os.File, size int64) error { return truncate(f, size) }

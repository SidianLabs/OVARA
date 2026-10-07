//go:build !windows

package appendfile

import "os"

func truncate(f *os.File, size int64) error { return f.Truncate(size) }

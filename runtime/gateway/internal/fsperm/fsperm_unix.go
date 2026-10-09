//go:build !windows

package fsperm

import "os"

func openToOthers(st os.FileInfo) bool { return st.Mode().Perm()&0o077 != 0 }

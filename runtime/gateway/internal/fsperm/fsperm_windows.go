//go:build windows

package fsperm

import "os"

func openToOthers(os.FileInfo) bool { return false }

// Package persist provides durability helpers shared by the file-backed
// stores: atomic whole-file replacement (write tmp + fsync + rename + dir
// fsync) so a crash mid-write cannot corrupt an existing store file.
package persist

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path atomically: it writes to a temp file in
// the same directory, fsyncs it, renames it over path, then fsyncs the
// directory so the rename is durable. A crash at any point leaves either the
// old or the new file intact — never a truncated one.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("failed to write temp file: %w", err))
	}
	if err := tmp.Chmod(perm); err != nil {
		return cleanup(fmt.Errorf("failed to chmod temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("failed to sync temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	// fsync the directory so the rename itself is durable across a crash.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

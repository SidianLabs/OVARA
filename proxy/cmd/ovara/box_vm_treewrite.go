//go:build linux || darwin

package main

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// writeTreeFile writes dir as a tar to out, readable by the guest's own user
// (the one the host copies files out as) and by no one who could change it.
func writeTreeFile(dir, out string) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // a path the host chose, created fresh
	if err != nil {
		return err
	}
	if err := writeTree(dir, f, treeMaxBytes, treeMaxEntries); err != nil {
		f.Close()
		os.Remove(out)
		return err
	}
	return f.Close()
}

// writeTree writes dir's directories, regular files and symbolic links to
// w, links as links and every file opened without following one. Anything
// else (a FIFO, a device, a socket) is left out and said so: reading a FIFO
// the agent left would hang, and a device is not a project file.
func writeTree(dir string, w io.Writer, maxBytes int64, maxEntries int) error {
	tw := tar.NewWriter(w)
	var total int64
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if n++; n > maxEntries {
			return fmt.Errorf("more than %d entries", maxEntries)
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := int64(info.Mode().Perm())
		switch {
		case info.IsDir():
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: rel + "/", Mode: mode})
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: rel, Linkname: target, Mode: 0o777})
		case info.Mode().IsRegular():
			if total += info.Size(); total > maxBytes {
				return fmt.Errorf("more than %d bytes of files", maxBytes)
			}
			fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			f := os.NewFile(uintptr(fd), p)
			defer f.Close()
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: mode, Size: info.Size()}); err != nil {
				return err
			}
			written, err := io.Copy(tw, io.LimitReader(f, info.Size()))
			if err != nil {
				return err
			}
			if written != info.Size() {
				return fmt.Errorf("%s changed while it was read", rel)
			}
			return nil
		default:
			fmt.Fprintf(os.Stderr, "[ovara] left in the box (not a file, directory or link): %s\n", termSafe(rel))
			return nil
		}
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

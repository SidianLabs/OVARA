package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// A VM's workspace comes back to the host as one tar the guest writes after
// the agent has exited (writeTree, box_vm_guest.go): directories, regular
// files and symbolic links, nothing else, symlinks kept as links. The host
// unpacks it into a fresh directory with extractTree, which trusts nothing
// in it: the agent decided every name and link.

// Limits on what a workspace can bring back: well past any project, small
// enough that a tar built to exhaust the host's disk stops early.
const (
	treeMaxBytes   = 8 << 30 // file content, in total
	treeMaxEntries = 1 << 20
)

// extractTree unpacks a workspace tar into dir, which must not exist yet.
// It refuses, and stops at, anything that could write outside dir: an
// absolute name, a ".." component, a path through a symbolic link already
// unpacked, a second entry for the same path, or an entry type other than
// a directory, a regular file or a link. Set-id bits are dropped.
func extractTree(r io.Reader, dir string, maxBytes int64, maxEntries int) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("workspace from the box: %w", err)
		}
		if n >= maxEntries {
			return fmt.Errorf("workspace from the box: more than %d entries", maxEntries)
		}
		rel, err := treeName(h.Name)
		if err != nil {
			return err
		}
		if err := parentsAreDirs(dir, rel); err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		mode := os.FileMode(h.Mode & 0o777) //nolint:gosec // masked to the nine permission bits before the conversion
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dst, mode|0o700); err != nil {
				return fmt.Errorf("workspace from the box: %s: %w", rel, err)
			}
		case tar.TypeReg:
			if h.Size < 0 || total+h.Size > maxBytes {
				return fmt.Errorf("workspace from the box: more than %d bytes of files", maxBytes)
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode|0o600) //nolint:gosec // inside the fresh directory, checked above
			if err != nil {
				return fmt.Errorf("workspace from the box: %s: %w", rel, err)
			}
			written, err := io.Copy(f, io.LimitReader(tr, h.Size))
			cerr := f.Close()
			if err != nil || cerr != nil || written != h.Size {
				return fmt.Errorf("workspace from the box: %s: short or failed write", rel)
			}
			total += written
		case tar.TypeSymlink:
			// stored as a link and never followed here; what the link may
			// bring back is the commit-back's decision, as for any box
			if err := os.Symlink(h.Linkname, dst); err != nil {
				return fmt.Errorf("workspace from the box: %s: %w", rel, err)
			}
		default:
			return fmt.Errorf("workspace from the box: %s: entry type %q is not a directory, file or link", rel, h.Typeflag)
		}
	}
}

// treeName checks one entry name: relative, clean, no "..", not empty.
func treeName(name string) (string, error) {
	n := strings.TrimSuffix(name, "/")
	if n == "" || path.IsAbs(n) || strings.HasPrefix(n, `\`) || strings.Contains(n, `\`) {
		return "", fmt.Errorf("workspace from the box: refusing entry %q", name)
	}
	if path.Clean(n) != n {
		return "", fmt.Errorf("workspace from the box: refusing entry %q (not a clean path)", name)
	}
	for _, c := range strings.Split(n, "/") {
		if c == ".." || c == "." || c == "" {
			return "", fmt.Errorf("workspace from the box: refusing entry %q", name)
		}
	}
	return n, nil
}

// parentsAreDirs requires every parent of rel inside dir to be a real
// directory unpacked earlier, never a symbolic link.
func parentsAreDirs(dir, rel string) error {
	parts := strings.Split(rel, "/")
	cur := dir
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		st, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("workspace from the box: %s: parent %s missing", rel, p)
		}
		if !st.IsDir() {
			return fmt.Errorf("workspace from the box: %s: goes through %s, which is not a directory", rel, p)
		}
	}
	return nil
}

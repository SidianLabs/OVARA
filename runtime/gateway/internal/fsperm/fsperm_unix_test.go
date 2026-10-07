//go:build !windows

package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenToOthers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if OpenToOthers(st) {
		t.Fatal("0600 must not be reported open")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(p)
	if !OpenToOthers(st) {
		t.Fatal("0644 must be reported open")
	}
}

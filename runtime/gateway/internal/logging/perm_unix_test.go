//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"testing"
)

// The decision log names every resource the agent touched: owner-only,
// in an owner-only directory, and an older world-readable log is tightened.
func TestDecisionLogger_OwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "log")
	logFile := filepath.Join(dir, "decisions.jsonl")
	l, err := NewDecisionLogger(logFile)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	for path, want := range map[string]os.FileMode{dir: 0o700, logFile: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %#o, want %#o", path, fi.Mode().Perm(), want)
		}
	}
	os.Chmod(logFile, 0o644)
	l, err = NewDecisionLogger(logFile)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if fi, _ := os.Stat(logFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("existing log left at %#o", fi.Mode().Perm())
	}
}

//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeccompOptOutNotes(t *testing.T) {
	if got := seccompOptOutNotes(false, false, true, true); len(got) != 0 {
		t.Errorf("a default run prints notes: %v", got)
	}
	got := strings.Join(seccompOptOutNotes(true, true, true, true), "\n")
	for _, want := range []string{
		"-allow-user-namespaces", "Docker's default profile still refuses them",
		"-allow-debuggers", "-no-command-gate", "perf_event_open",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("tier 2 with the gate: notes lack %q:\n%s", want, got)
		}
	}
	// without the gate there is nothing to advise against, and outside tier 2
	// Docker's profile is not in play
	got = strings.Join(seccompOptOutNotes(true, true, false, false), "\n")
	for _, bad := range []string{"-no-command-gate", "Docker"} {
		if strings.Contains(got, bad) {
			t.Errorf("tier 1 without the gate mentions %q:\n%s", bad, got)
		}
	}
}

func TestCheckRunnableByAll(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ovara")
	if err := os.WriteFile(p, []byte("x"), 0o700); err != nil { //nolint:gosec // a test binary stand-in
		t.Fatal(err)
	}
	if err := checkRunnableByAll(p); err == nil {
		t.Error("a binary only its owner may run was accepted")
	}
	if err := os.Chmod(p, 0o755); err != nil { //nolint:gosec // the mode under test
		t.Fatal(err)
	}
	if err := checkRunnableByAll(p); err != nil {
		t.Errorf("a 0755 binary was refused: %v", err)
	}
	if err := checkRunnableByAll(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing binary was accepted")
	}
}

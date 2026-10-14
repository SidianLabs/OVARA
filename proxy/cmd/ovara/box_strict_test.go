//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"ovara.proxy/internal/lockfiles"
)

// -untrusted-lockfiles: the lockfile is still read (and named), but pins
// nothing, so the proxy's gate asks about every package.
func TestStrictPins_UntrustedLockfiles(t *testing.T) {
	d := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-` + "AAAA" + `"}}}`
	if err := os.WriteFile(filepath.Join(d, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	pins, files := strictPins(d, false)
	if _, ok := pins["npm:left-pad@1.3.0"]; !ok || len(files) != 1 {
		t.Fatalf("trusted: pins=%v files=%v", pins, files)
	}
	pins, files = strictPins(d, true)
	if len(pins) != 0 || len(files) != 1 {
		t.Fatalf("untrusted: pins=%v files=%v", pins, files)
	}
	if got := lockfiles.ParsePins(lockfiles.FormatPins(pins)); len(got) != 0 {
		t.Fatalf("the gate's file pins %v", got)
	}
}

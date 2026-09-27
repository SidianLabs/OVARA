package persist

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The atomic write is the durability boundary every file-backed store
// relies on: content lands whole, permissions hold, and a rewrite
// replaces rather than truncates.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "store.json") // MkdirAll covers this
	if err := WriteFileAtomic(p, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte(`{"a":1}`)) {
		t.Fatalf("content mismatch: %q", data)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 0600", st.Mode().Perm())
	}
	// Rewrite replaces the old file completely — never a mix.
	if err := WriteFileAtomic(p, []byte(`{"b":2}`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	data, _ = os.ReadFile(p)
	if !bytes.Equal(data, []byte(`{"b":2}`)) {
		t.Fatalf("rewrite content mismatch: %q", data)
	}
	// No temp litter survives a successful write.
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || bytes.HasPrefix([]byte(e.Name()), []byte(".atomic-")) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// An unwritable destination fails as an error — the caller (a store's
// flush path) must see the failure, not a silent partial file.
func TestWriteFileAtomic_UnwritableDir(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A path inside a regular file: MkdirAll/CreateTemp must error.
	if err := WriteFileAtomic(filepath.Join(f, "sub", "x"), []byte("y"), 0o600); err == nil {
		t.Fatal("write into a file-as-dir succeeded")
	}
}

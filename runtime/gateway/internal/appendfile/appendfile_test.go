package appendfile

import (
	"os"
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/internal/flock"
)

func TestTruncateAppendHandleWhileLocked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "j.jsonl")
	if err := os.WriteFile(p, []byte("{\"a\":1}\n{\"torn"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := flock.Lock(f); err != nil {
		t.Fatal(err)
	}
	if err := Truncate(f, 8); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := f.Write([]byte("{\"b\":2}\n")); err != nil {
		t.Fatalf("append after truncate: %v", err)
	}
	if err := flock.Unlock(f); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":1}\n{\"b\":2}\n"; string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

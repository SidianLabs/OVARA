package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const doc = `{"version":"%s","rules":[{"action_type":"shell","environment":"*","allow":true}]}`

func waitPolicyEvent(t *testing.T, w *Watcher, what string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-w.Events():
			if w.IsPolicyEvent(ev) {
				return
			}
		case <-deadline:
			t.Fatalf("no policy-change event for: %s", what)
		}
	}
}

// Hot reload must survive both ways people save a file: writing it in place,
// and writing a temp file then renaming it over the original (most editors,
// and this repo's own WriteFile). A watch on the file itself loses track of
// the rename; watching the directory does not.
func TestWatcher_SeesInPlaceWriteAndRenameReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(doc, "v1")), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStoreFromFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(NewLocalFileSource(path, "", store))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Watch(path); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(fmt.Sprintf(doc, "v2")), 0o600); err != nil {
		t.Fatal(err)
	}
	waitPolicyEvent(t, w, "in-place write")

	for i, v := range []string{"v3", "v4", "v5"} { // several renames: the watch must stay alive
		tmp := filepath.Join(dir, ".policy.tmp")
		if err := os.WriteFile(tmp, []byte(fmt.Sprintf(doc, v)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		waitPolicyEvent(t, w, "rename-over #"+string(rune('1'+i)))
	}
	if err := w.Reload(); err != nil {
		t.Fatalf("reload after renames: %v", err)
	}
}

func TestWatcher_IgnoresOtherFilesInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(fmt.Sprintf(doc, "v1")), 0o600)
	store, _ := LoadStoreFromFile(path, "")
	w, err := NewWatcher(NewLocalFileSource(path, "", store))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.Watch(path)
	os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o600)
	select {
	case ev := <-w.Events():
		if w.IsPolicyEvent(ev) {
			t.Fatalf("an unrelated file counted as a policy change: %v", ev)
		}
	case <-time.After(500 * time.Millisecond):
	}
}



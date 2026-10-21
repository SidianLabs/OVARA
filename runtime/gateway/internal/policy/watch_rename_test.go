package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
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

// On kqueue a rename over the file can surface only as the old inode's Remove
// (see IsPolicyEvent). It must count, or hot reload misses that save.
func TestWatcher_RemoveOfPolicyFileCounts(t *testing.T) {
	w := &Watcher{base: "policy.json"}
	dir := t.TempDir()
	for _, op := range []fsnotify.Op{fsnotify.Write, fsnotify.Create, fsnotify.Rename, fsnotify.Remove} {
		if !w.IsPolicyEvent(fsnotify.Event{Name: filepath.Join(dir, "policy.json"), Op: op}) {
			t.Errorf("%v of policy.json is not a policy event", op)
		}
	}
	if w.IsPolicyEvent(fsnotify.Event{Name: filepath.Join(dir, "policy.json"), Op: fsnotify.Chmod}) {
		t.Error("a chmod alone counted as a policy change")
	}
	if w.IsPolicyEvent(fsnotify.Event{Name: filepath.Join(dir, ".policy.tmp"), Op: fsnotify.Remove}) {
		t.Error("removing the temp file counted as a policy change")
	}
}

func TestFileChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte("a"), 0o600)
	a, _ := os.Stat(path)
	same, _ := os.Stat(path)
	if fileChanged(a, same) {
		t.Error("an untouched file counted as changed")
	}
	tmp := filepath.Join(dir, ".policy.tmp")
	os.WriteFile(tmp, []byte("b"), 0o600)
	os.Rename(tmp, path)
	replaced, _ := os.Stat(path)
	if !fileChanged(a, replaced) {
		t.Error("a file renamed over the original did not count as changed")
	}
	if !fileChanged(replaced, nil) || !fileChanged(nil, replaced) {
		t.Error("the file disappearing or appearing did not count as changed")
	}
	if fileChanged(nil, nil) {
		t.Error("a file missing both times counted as changed")
	}
}

// The poll alone must report a rename over the file, for the case where the
// OS delivers no notification for it.
func TestWatcher_PollReportsReplacedFile(t *testing.T) {
	old := pollInterval
	pollInterval = 20 * time.Millisecond
	defer func() { pollInterval = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(fmt.Sprintf(doc, "v1")), 0o600)
	w := &Watcher{base: "policy.json", path: path, events: make(chan fsnotify.Event, 4), done: make(chan struct{})}
	w.wg.Add(1)
	go w.poll()
	defer func() { close(w.done); w.wg.Wait() }()

	tmp := filepath.Join(dir, ".policy.tmp")
	os.WriteFile(tmp, []byte(fmt.Sprintf(doc, "v2")), 0o600)
	os.Rename(tmp, path)
	select {
	case ev := <-w.events:
		if !w.IsPolicyEvent(ev) {
			t.Fatalf("poll sent a non-policy event: %v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll did not report the replaced file")
	}
}

func TestWatcher_CloseEndsEventsAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(fmt.Sprintf(doc, "v1")), 0o600)
	store, _ := LoadStoreFromFile(path, "")
	w, err := NewWatcher(NewLocalFileSource(path, "", store))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(path); err != nil {
		t.Fatal(err)
	}
	w.Close()
	w.Close()
	for range w.Events() { // must terminate: Close closes the channel
	}
}

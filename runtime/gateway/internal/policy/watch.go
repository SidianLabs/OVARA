package policy

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// pollInterval is how often the watcher re-checks the policy file itself, as
// a backstop for change notifications the OS does not deliver (see Watch).
var pollInterval = 500 * time.Millisecond

type Watcher struct {
	watcher *fsnotify.Watcher
	source  *LocalFileSource
	base    string
	path    string

	events    chan fsnotify.Event
	done      chan struct{}
	wg        sync.WaitGroup
	pollOnce  sync.Once
	closeOnce sync.Once
}

func NewWatcher(source *LocalFileSource) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		watcher: fw,
		source:  source,
		events:  make(chan fsnotify.Event, 16),
		done:    make(chan struct{}),
	}
	w.wg.Add(1)
	go w.forward()
	return w, nil
}

// Watch watches the file's DIRECTORY, not the file itself. Many editors and
// tools save by writing a temp file and renaming it over the original; an
// inotify watch on the file's inode is gone after that and every later edit
// is silently missed. Events for other files in the directory are delivered
// too, so consumers filter with IsPolicyEvent.
//
// It also polls the file every pollInterval. On kqueue (macOS, BSD) fsnotify
// finds new files by diffing the directory listing, and a rename over the
// same name that races with fsnotify re-watching the file can produce no
// event at all: the directory notifications are merged and the name was
// never missing from the listing. The poll compares a hash of the file's
// contents, so a replaced or edited file is always noticed. (File identity
// is no help here: on Windows os.SameFile resolves it lazily by path, so
// after a rename both sides name the new file.) Policy files are small, so
// reading one twice a second costs nothing.
func (w *Watcher) Watch(filePath string) error {
	w.base = filepath.Base(filePath)
	w.path = filePath
	if err := w.watcher.Add(filepath.Dir(filePath)); err != nil {
		return err
	}
	w.pollOnce.Do(func() {
		w.wg.Add(1)
		go w.poll()
	})
	return nil
}

// IsPolicyEvent reports whether ev means "the policy file changed": a write,
// a create, a rename, or a remove of the watched file name.
//
// Remove counts because on kqueue a rename over the file can surface only as
// the old inode's delete. The new file is already in place by then, so
// reloading picks it up; if the file really was deleted, the reload fails and
// the current policy stays in force.
func (w *Watcher) IsPolicyEvent(ev fsnotify.Event) bool {
	if filepath.Base(ev.Name) != w.base {
		return false
	}
	return ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) ||
		ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Remove)
}

// Events delivers fsnotify's events for the directory plus a synthetic Write
// for the policy file whenever the poll sees it change. It is closed by Close.
func (w *Watcher) Events() <-chan fsnotify.Event {
	return w.events
}

func (w *Watcher) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		err = w.watcher.Close()
		w.wg.Wait()
		close(w.events)
	})
	return err
}

func (w *Watcher) Reload() error {
	return w.source.Reload()
}

func (w *Watcher) forward() {
	defer w.wg.Done()
	for ev := range w.watcher.Events {
		select {
		case w.events <- ev:
		case <-w.done:
			return
		}
	}
}

func (w *Watcher) poll() {
	defer w.wg.Done()
	last := snapshot(w.path)
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-t.C:
		}
		cur := snapshot(w.path)
		if cur == last {
			continue
		}
		last = cur
		select {
		case w.events <- fsnotify.Event{Name: w.path, Op: fsnotify.Write}:
		case <-w.done:
			return
		}
	}
}

// fileState is what the poll compares: whether the file could be read, and a
// hash of its contents.
type fileState struct {
	readable bool
	sum      [sha256.Size]byte
}

func snapshot(path string) fileState {
	b, err := os.ReadFile(path)
	if err != nil {
		return fileState{}
	}
	return fileState{readable: true, sum: sha256.Sum256(b)}
}

package policy

import (
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	watcher *fsnotify.Watcher
	source  *LocalFileSource
	base    string
}

func NewWatcher(source *LocalFileSource) (*Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{watcher: w, source: source}, nil
}

// Watch watches the file's DIRECTORY, not the file itself. Many editors and
// tools save by writing a temp file and renaming it over the original; an
// inotify watch on the file's inode is gone after that and every later edit
// is silently missed. Events for other files in the directory are delivered
// too, so consumers filter with IsPolicyEvent.
func (w *Watcher) Watch(filePath string) error {
	w.base = filepath.Base(filePath)
	return w.watcher.Add(filepath.Dir(filePath))
}

// IsPolicyEvent reports whether ev means "the policy file changed": a write,
// a create, or a rename into place, of the watched file name.
func (w *Watcher) IsPolicyEvent(ev fsnotify.Event) bool {
	if filepath.Base(ev.Name) != w.base {
		return false
	}
	return ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) || ev.Has(fsnotify.Rename)
}

func (w *Watcher) Events() <-chan fsnotify.Event {
	return w.watcher.Events
}

func (w *Watcher) Close() error {
	return w.watcher.Close()
}

func (w *Watcher) Reload() error {
	return w.source.Reload()
}
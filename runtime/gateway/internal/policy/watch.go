package policy

import (
	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	watcher *fsnotify.Watcher
	source  *LocalFileSource
}

func NewWatcher(source *LocalFileSource) (*Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{watcher: w, source: source}, nil
}

func (w *Watcher) Watch(filePath string) error {
	return w.watcher.Add(filePath)
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
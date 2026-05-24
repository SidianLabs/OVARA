package policy

type PolicySource interface {
	Load() (*Store, error)
	Version() string
	Reload() error
}

type InMemorySource struct {
	store *Store
}

func NewInMemorySource(store *Store) *InMemorySource {
	return &InMemorySource{store: store}
}

func (s *InMemorySource) Load() (*Store, error) {
	return s.store, nil
}

func (s *InMemorySource) Version() string {
	return s.store.Version()
}

func (s *InMemorySource) Reload() error {
	return nil
}

type LocalFileSource struct {
	filePath string
	version  string
	store    *Store
}

func NewLocalFileSource(filePath string, version string, store *Store) *LocalFileSource {
	return &LocalFileSource{filePath: filePath, version: version, store: store}
}

func (s *LocalFileSource) Load() (*Store, error) {
	return LoadStoreFromFile(s.filePath, s.version)
}

func (s *LocalFileSource) Version() string {
	return s.version
}

func (s *LocalFileSource) Reload() error {
	return s.store.Reload()
}

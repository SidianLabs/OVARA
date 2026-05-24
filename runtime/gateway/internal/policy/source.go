package policy

type PolicySource interface {
	Load() (*Store, error)
	Version() string
	Reload() (*Store, error)
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

func (s *InMemorySource) Reload() (*Store, error) {
	return s.store, nil
}

type LocalFileSource struct {
	filePath string
	version  string
}

func NewLocalFileSource(filePath string, version string) *LocalFileSource {
	return &LocalFileSource{filePath: filePath, version: version}
}

func (s *LocalFileSource) Load() (*Store, error) {
	return LoadStoreFromFile(s.filePath, s.version)
}

func (s *LocalFileSource) Version() string {
	return s.version
}

func (s *LocalFileSource) Reload() (*Store, error) {
	return s.Load()
}

func LoadStoreFromFile(filePath string, version string) (*Store, error) {
	store := NewStore(version)
	if version == "" {
		version = "v1-default"
	}
	store.version = version
	return store, nil
}
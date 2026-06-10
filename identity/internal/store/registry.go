package store

import (
	"fmt"
	"sync"

	"ovara.identity/internal/crypto"
)

type Registry struct {
	mu         sync.RWMutex
	identities map[string]*crypto.AgentIdentity
}

func NewRegistry() *Registry {
	return &Registry{
		identities: make(map[string]*crypto.AgentIdentity),
	}
}

func (r *Registry) Register(id *crypto.AgentIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.identities[id.ID]; exists {
		return fmt.Errorf("identity already registered: %s", id.ID)
	}
	for _, existing := range r.identities {
		if existing.SubjectID == id.SubjectID && existing.Issuer == id.Issuer {
			return fmt.Errorf("identity with subject_id=%q and issuer=%q already exists", id.SubjectID, id.Issuer)
		}
	}
	r.identities[id.ID] = id
	return nil
}

func (r *Registry) Get(id string) (*crypto.AgentIdentity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	identity, ok := r.identities[id]
	return identity, ok
}

func (r *Registry) List() []*crypto.AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*crypto.AgentIdentity, 0, len(r.identities))
	for _, id := range r.identities {
		result = append(result, id)
	}
	return result
}

func (r *Registry) ListActive() []*crypto.AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*crypto.AgentIdentity
	for _, id := range r.identities {
		if id.IsActive() {
			result = append(result, id)
		}
	}
	return result
}

func (r *Registry) Suspend(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identities[id]
	if !ok {
		return fmt.Errorf("identity not found: %s", id)
	}
	identity.Suspend()
	return nil
}

func (r *Registry) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identities[id]
	if !ok {
		return fmt.Errorf("identity not found: %s", id)
	}
	identity.Revoke()
	return nil
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.identities)
}

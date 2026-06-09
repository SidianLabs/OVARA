package identity

import (
	"fmt"
	"sync"
)

type Registry struct {
	mu         sync.RWMutex
	identities map[string]*AgentIdentity
}

func NewRegistry() *Registry {
	return &Registry{
		identities: make(map[string]*AgentIdentity),
	}
}

func (r *Registry) Register(id *AgentIdentity) error {
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

func (r *Registry) Get(id string) (*AgentIdentity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	identity, ok := r.identities[id]
	return identity, ok
}

func (r *Registry) List() []*AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*AgentIdentity, 0, len(r.identities))
	for _, id := range r.identities {
		result = append(result, id)
	}
	return result
}

func (r *Registry) ListActive() []*AgentIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*AgentIdentity
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

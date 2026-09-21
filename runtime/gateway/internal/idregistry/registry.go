// Package idregistry implements the P2.2 stable-identity + credential
// lifecycle store.
//
// Model: CREDENTIAL (fingerprint only — the raw token is never stored)
// is durably bound to a stable IDENTITY. Authentication resolves a
// bearer token to its bound identity; the caller can never choose an
// identity — bindIdentity enforcement downstream is unchanged, only
// the principal now comes from the registry instead of a fresh hash.
//
// Migration rule: a config-seeded credential gets identity id =
// "ag_"/"op_" + sha256(token)[:16] — the exact RC1 principal string.
// The identity namespace IS the principal namespace, so delegations,
// leases, approvals, and receipts referencing the old principal keep
// their meaning across rotation.
//
// Persistence: whole-file JSON via persist.WriteFileAtomic. Mutations
// are clone → mutate → persist → commit; a failed write never takes
// effect (fail closed). Config seeding is idempotent and
// NON-RESURRECTING: a fingerprint already in the registry keeps its
// stored state, so restarting with a stale config cannot revive a
// revoked credential. Removing a token from config DOES revoke its
// config-origin credential at next startup (config is the operator's
// source of truth for seeded credentials).
package idregistry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/persist"
)

type IdentityStatus string

const (
	StatusActive    IdentityStatus = "active"
	StatusSuspended IdentityStatus = "suspended"
	StatusRetired   IdentityStatus = "retired"
	StatusMigrated  IdentityStatus = "migrated"
)

type CredState string

const (
	CredActive     CredState = "active"
	CredRotating   CredState = "rotating" // dual-valid until GraceUntil
	CredSuperseded CredState = "superseded"
	CredRevoked    CredState = "revoked"
	CredExpired    CredState = "expired"
)

type Identity struct {
	ID          string         `json:"id"`
	Role        string         `json:"role"` // "agent" | "operator"
	Status      IdentityStatus `json:"status"`
	MigratedTo  string         `json:"migrated_to,omitempty"`
	Generation  int            `json:"generation"`
	CreatedAt   time.Time      `json:"created_at"`
	SuspendedAt *time.Time     `json:"suspended_at,omitempty"`
	RetiredAt   *time.Time     `json:"retired_at,omitempty"`
}

type Credential struct {
	Fingerprint string     `json:"fingerprint"` // sha256(token) hex — never the token
	IdentityID  string     `json:"identity_id"`
	State       CredState  `json:"state"`
	Origin      string     `json:"origin"` // "config" | "api"
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	GraceUntil  *time.Time `json:"grace_until,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PrincipalID derives the migration-stable identity id for a
// config-seeded credential — identical to the RC1 principal.
func PrincipalID(role, token string) string {
	prefix := "ag_"
	if role == "operator" {
		prefix = "op_"
	}
	return prefix + Fingerprint(token)[:16]
}

var idRe = regexp.MustCompile(`^(ag|op)_[a-zA-Z0-9_-]{3,64}$`)

func roleForID(id string) (string, bool) {
	switch {
	case len(id) > 3 && id[:3] == "ag_":
		return "agent", true
	case len(id) > 3 && id[:3] == "op_":
		return "operator", true
	}
	return "", false
}

type fileState struct {
	Identities  []*Identity   `json:"identities"`
	Credentials []*Credential `json:"credentials"`
}

// Registry is the identity+credential store. Single gateway = single
// trust domain: one file, one writer. Multi-gateway consistency is a
// documented non-goal for P2.2.
type Registry struct {
	path string
	mu   sync.RWMutex
	ids  map[string]*Identity
	cred map[string]*Credential // by fingerprint
}

func NewInMemory() *Registry {
	return &Registry{ids: map[string]*Identity{}, cred: map[string]*Credential{}}
}

// Open loads or creates the registry file. Corrupt state fails open:
// the registry cannot prove identity state, so startup must refuse.
func Open(path string) (*Registry, error) {
	r := NewInMemory()
	r.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("identity registry: read %s: %w", path, err)
	}
	var fs fileState
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, fmt.Errorf("identity registry: corrupt %s: %w", path, err)
	}
	for _, id := range fs.Identities {
		r.ids[id.ID] = id
	}
	for _, c := range fs.Credentials {
		r.cred[c.Fingerprint] = c
	}
	return r, nil
}

// persist writes the whole registry atomically. Caller holds mu.
func (r *Registry) persist() error {
	if r.path == "" {
		return nil // in-memory mode — documented non-durable
	}
	fs := fileState{Identities: make([]*Identity, 0, len(r.ids)),
		Credentials: make([]*Credential, 0, len(r.cred))}
	for _, id := range r.ids {
		fs.Identities = append(fs.Identities, id)
	}
	for _, c := range r.cred {
		fs.Credentials = append(fs.Credentials, c)
	}
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return err
	}
	return persist.WriteFileAtomic(r.path, data, 0600)
}

func (r *Registry) clone() (*Registry, error) {
	c := &Registry{path: r.path, ids: map[string]*Identity{}, cred: map[string]*Credential{}}
	for k, v := range r.ids {
		cp := *v
		c.ids[k] = &cp
	}
	for k, v := range r.cred {
		cp := *v
		c.cred[k] = &cp
	}
	return c, nil
}

// mutate applies fn to a clone, persists, then commits — so a failed
// persist leaves the live registry untouched. Each pass also
// normalizes time-based credential states (Authenticate denies them
// on the pure-read path regardless; this keeps the stored record
// honest).
func (r *Registry) mutate(fn func(*Registry) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.clone()
	if err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	c.normalize()
	if err := c.persist(); err != nil {
		return err
	}
	r.ids, r.cred = c.ids, c.cred
	return nil
}

// normalize transitions time-bound credential states. Caller holds mu.
func (r *Registry) normalize() {
	now := time.Now().UTC()
	for _, cred := range r.cred {
		switch cred.State {
		case CredActive:
			if cred.ExpiresAt != nil && !now.Before(*cred.ExpiresAt) {
				cred.State = CredExpired
			}
		case CredRotating:
			if cred.GraceUntil == nil || !now.Before(*cred.GraceUntil) {
				cred.State = CredSuperseded
			}
		}
	}
}

func genToken() string {
	return "tok_" + hex.EncodeToString(func() []byte { b := make([]byte, 24); rand.Read(b); return b }())
}

func genID(role string) string {
	prefix := "ag_"
	if role == "operator" {
		prefix = "op_"
	}
	return prefix + hex.EncodeToString(func() []byte { b := make([]byte, 12); rand.Read(b); return b }())[:16]
}

// SeedConfig registers each config token idempotently and revokes
// config-origin credentials of the same role that are no longer
// present in config. Never resurrects existing records.
func (r *Registry) SeedConfig(tokens []string, role string) error {
	present := map[string]bool{}
	for _, t := range tokens {
		present[Fingerprint(t)] = true
	}
	return r.mutate(func(c *Registry) error {
		now := time.Now().UTC()
		for _, t := range tokens {
			fp := Fingerprint(t)
			if _, exists := c.cred[fp]; exists {
				continue // non-resurrecting
			}
			idID := PrincipalID(role, t)
			if _, exists := c.ids[idID]; !exists {
				c.ids[idID] = &Identity{ID: idID, Role: role,
					Status: StatusActive, Generation: 1, CreatedAt: now}
			}
			c.cred[fp] = &Credential{Fingerprint: fp, IdentityID: idID,
				State: CredActive, Origin: "config", IssuedAt: now}
		}
		// Config absence = revocation for config-origin creds of this role.
		for _, cred := range c.cred {
			if cred.Origin != "config" || present[cred.Fingerprint] {
				continue
			}
			id := c.ids[cred.IdentityID]
			if id == nil || id.Role != role {
				continue
			}
			if cred.State == CredActive || cred.State == CredRotating {
				cred.State = CredRevoked
				cred.RevokedAt = &now
			}
		}
		return nil
	})
}

// Authenticate resolves a bearer token to (identityID, role, ok).
// Fails closed on any invalid state: unknown, revoked, superseded,
// expired, out-of-grace rotating, or non-active identity.
func (r *Registry) Authenticate(token string) (string, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.authenticateLocked(token, time.Now().UTC())
}

func (r *Registry) authenticateLocked(token string, now time.Time) (string, string, bool) {
	cred, ok := r.cred[Fingerprint(token)]
	if !ok {
		return "", "", false
	}
	// Pure read — no lazy writes under RLock. Expired/superseded-by-time
	// credentials deny here; their recorded state catches up on the next
	// mutation pass (normalizeLocked).
	switch cred.State {
	case CredActive:
		if cred.ExpiresAt != nil && !now.Before(*cred.ExpiresAt) {
			return "", "", false
		}
	case CredRotating:
		if cred.GraceUntil == nil || !now.Before(*cred.GraceUntil) {
			return "", "", false
		}
	default:
		return "", "", false
	}
	id, ok := r.ids[cred.IdentityID]
	if !ok || id.Status != StatusActive {
		return "", "", false
	}
	return id.ID, id.Role, true
}

// Register creates an identity + first credential. idHint empty →
// server-generated. token empty → server-generated (returned once).
func (r *Registry) Register(role, idHint, token string, expiresAt *time.Time) (id, tok string, err error) {
	err = r.mutate(func(c *Registry) error {
		now := time.Now().UTC()
		id = idHint
		if id == "" {
			for tries := 0; tries < 8; tries++ {
				id = genID(role)
				if _, taken := c.ids[id]; !taken {
					break
				}
			}
		}
		if !idRe.MatchString(id) {
			return fmt.Errorf("identity_id %q must match ag_/op_ prefix + 3..64 chars", id)
		}
		if prefixRole, _ := roleForID(id); prefixRole != role {
			return fmt.Errorf("identity_id prefix implies role %q, cannot register as %q", prefixRole, role)
		}
		if _, taken := c.ids[id]; taken {
			return fmt.Errorf("identity %q already exists — rotate, do not re-register", id)
		}
		if token == "" {
			token = genToken()
		}
		fp := Fingerprint(token)
		if _, exists := c.cred[fp]; exists {
			return fmt.Errorf("credential already bound to another identity")
		}
		c.ids[id] = &Identity{ID: id, Role: role, Status: StatusActive,
			Generation: 1, CreatedAt: now}
		c.cred[fp] = &Credential{Fingerprint: fp, IdentityID: id,
			State: CredActive, Origin: "api", IssuedAt: now, ExpiresAt: expiresAt}
		tok = token
		return nil
	})
	return id, tok, err
}

// Rotate binds a new credential to the same identity. Existing active
// credentials enter CredRotating for graceSecs (bounded), then
// supersede. Empty newToken → server-generated.
func (r *Registry) Rotate(identityID, newToken string, graceSecs int) (string, error) {
	const maxGrace = 24 * 3600
	if graceSecs <= 0 {
		graceSecs = 300
	}
	if graceSecs > maxGrace {
		return "", fmt.Errorf("grace %ds exceeds max %ds", graceSecs, maxGrace)
	}
	tok := ""
	err := r.mutate(func(c *Registry) error {
		now := time.Now().UTC()
		id, ok := c.ids[identityID]
		if !ok {
			return fmt.Errorf("identity %q not found", identityID)
		}
		if id.Status == StatusRetired || id.Status == StatusMigrated {
			return fmt.Errorf("identity %q is %s — cannot rotate", identityID, id.Status)
		}
		if newToken == "" {
			newToken = genToken()
		}
		fp := Fingerprint(newToken)
		if _, exists := c.cred[fp]; exists {
			return fmt.Errorf("credential already bound to an identity")
		}
		graceUntil := now.Add(time.Duration(graceSecs) * time.Second)
		for _, cred := range c.cred {
			if cred.IdentityID == identityID && cred.State == CredActive {
				cred.State = CredRotating
				cred.GraceUntil = &graceUntil
			}
		}
		c.cred[fp] = &Credential{Fingerprint: fp, IdentityID: identityID,
			State: CredActive, Origin: "api", IssuedAt: now}
		id.Generation++
		tok = newToken
		return nil
	})
	return tok, err
}

// Revoke kills one credential by fingerprint or raw token.
func (r *Registry) Revoke(fingerprint string) error {
	return r.mutate(func(c *Registry) error {
		cred, ok := c.cred[fingerprint]
		if !ok {
			return fmt.Errorf("credential %s not found", fingerprint)
		}
		now := time.Now().UTC()
		cred.State = CredRevoked
		cred.RevokedAt = &now
		return nil
	})
}

func (r *Registry) RevokeToken(token string) error {
	return r.Revoke(Fingerprint(token))
}

// Transition applies an identity lifecycle action:
// suspend | resume | retire | migrate(migratedTo).
func (r *Registry) Transition(identityID, action, migratedTo string) error {
	return r.mutate(func(c *Registry) error {
		now := time.Now().UTC()
		id, ok := c.ids[identityID]
		if !ok {
			return fmt.Errorf("identity %q not found", identityID)
		}
		switch action {
		case "suspend":
			if id.Status != StatusActive {
				return fmt.Errorf("cannot suspend identity in state %s", id.Status)
			}
			id.Status = StatusSuspended
			id.SuspendedAt = &now
		case "resume":
			if id.Status != StatusSuspended {
				return fmt.Errorf("cannot resume identity in state %s", id.Status)
			}
			id.Status = StatusActive
			id.SuspendedAt = nil
		case "retire":
			id.Status = StatusRetired
			id.RetiredAt = &now
		case "migrate":
			if migratedTo == "" {
				return fmt.Errorf("migrate requires migrated_to")
			}
			if _, ok := c.ids[migratedTo]; !ok {
				return fmt.Errorf("migration target %q does not exist", migratedTo)
			}
			id.Status = StatusMigrated
			id.MigratedTo = migratedTo
			id.RetiredAt = &now
		default:
			return fmt.Errorf("unknown action %q", action)
		}
		return nil
	})
}

// StatusOf reports an identity's status — used by the continuation
// orchestrator to refuse executing suspended identities' queued work.
func (r *Registry) StatusOf(identityID string) (IdentityStatus, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.ids[identityID]
	if !ok {
		return "", false
	}
	return id.Status, true
}

// List returns redacted copies — fingerprint prefixes only.
func (r *Registry) List() ([]*Identity, []*Credential) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]*Identity, 0, len(r.ids))
	creds := make([]*Credential, 0, len(r.cred))
	for _, v := range r.ids {
		cp := *v
		ids = append(ids, &cp)
	}
	for _, v := range r.cred {
		cp := *v
		if len(cp.Fingerprint) > 12 {
			cp.Fingerprint = cp.Fingerprint[:12] + "…"
		}
		creds = append(creds, &cp)
	}
	return ids, creds
}

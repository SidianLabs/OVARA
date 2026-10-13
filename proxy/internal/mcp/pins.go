package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Pin is the approved definition of one tool.
type Pin struct {
	SHA256 string `json:"sha256"`
	// Description as approved (cut to maxPinnedDescription bytes), so that
	// a later change can be shown next to what was approved.
	Description string    `json:"description,omitempty"`
	ApprovedAt  time.Time `json:"approved_at"`
	ApprovalID  string    `json:"approval_id,omitempty"`
	// Refused is a later definition of this tool that was refused. Calls to
	// the tool are refused until a definition is approved again or the
	// server goes back to the approved one.
	Refused string `json:"refused_sha256,omitempty"`
}

const maxPinnedDescription = 4096

// Change is a tool whose definition differs from its pin.
type Change struct {
	Old Pin
	New Tool
}

// Drift is how a tool list differs from the pins of its server.
type Drift struct {
	// First is set when the server has no pins at all.
	First   bool
	New     []Tool
	Changed []Change
	// Restored are tools back at their approved definition after a refused
	// change.
	Restored []string
}

// Empty reports whether nothing needs a person.
func (d Drift) Empty() bool { return len(d.New) == 0 && len(d.Changed) == 0 }

type pinFile struct {
	Version int                       `json:"version"`
	Servers map[string]map[string]Pin `json:"servers"`
}

// Store holds the pins of every server, by server key ("host/path" for
// HTTP, "stdio:<name>" for a wrapped stdio server), in a JSON file. Several
// processes may share the file (the proxy and any `ovara mcp wrap`): each
// saves only the servers it changed, merged into what is on disk.
type Store struct {
	path    string
	mu      sync.Mutex
	servers map[string]map[string]Pin
	mine    map[string]bool // servers this process changed
}

// OpenStore loads the pin file at path (created on first save). An empty
// path keeps the pins in memory only.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, servers: map[string]map[string]Pin{}, mine: map[string]bool{}}
	if path == "" {
		return s, nil
	}
	f, err := readPinFile(path)
	if err != nil {
		return nil, err
	}
	s.servers = f.Servers
	return s, nil
}

func readPinFile(path string) (*pinFile, error) {
	f := &pinFile{Servers: map[string]map[string]Pin{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Servers == nil {
		f.Servers = map[string]map[string]Pin{}
	}
	return f, nil
}

// Lookup returns the pin of one tool.
func (s *Store) Lookup(server, tool string) (Pin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.servers[server][tool]
	return p, ok
}

// Drift compares a tool list with the server's pins.
func (s *Store) Drift(server string, tools []Tool) Drift {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins := s.servers[server]
	d := Drift{First: len(pins) == 0}
	for _, t := range tools {
		p, ok := pins[t.Name]
		switch {
		case !ok:
			d.New = append(d.New, t)
		case p.SHA256 != t.Hash:
			d.Changed = append(d.Changed, Change{Old: p, New: t})
		case p.Refused != "":
			d.Restored = append(d.Restored, t.Name)
		}
	}
	return d
}

// Approve pins tools as they are now.
func (s *Store) Approve(server string, tools []Tool, approvalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins := s.servers[server]
	if pins == nil {
		pins = map[string]Pin{}
		s.servers[server] = pins
	}
	now := time.Now().UTC()
	for _, t := range tools {
		pins[t.Name] = Pin{SHA256: t.Hash, Description: cut(t.Description, maxPinnedDescription), ApprovedAt: now, ApprovalID: approvalID}
	}
	s.mine[server] = true
	return s.saveLocked()
}

// Refuse records refused changes: calls to those tools are refused until a
// definition is approved again.
func (s *Store) Refuse(server string, changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pins := s.servers[server]
	for _, c := range changes {
		if p, ok := pins[c.New.Name]; ok {
			p.Refused = c.New.Hash
			pins[c.New.Name] = p
		}
	}
	s.mine[server] = true
	return s.saveLocked()
}

// Restore clears the refusal of tools that are back at their approved
// definition.
func (s *Store) Restore(server string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pins := s.servers[server]
	for _, n := range names {
		if p, ok := pins[n]; ok {
			p.Refused = ""
			pins[n] = p
		}
	}
	s.mine[server] = true
	return s.saveLocked()
}

// OtherTools maps the tool names pinned for every other server to that
// server (for the shadowing check). The file is read again first, so tools
// another process pinned are seen too.
func (s *Store) OtherTools(server string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path != "" {
		if f, err := readPinFile(s.path); err == nil {
			for k, v := range f.Servers {
				if !s.mine[k] {
					s.servers[k] = v
				}
			}
		}
	}
	out := map[string]string{}
	keys := make([]string, 0, len(s.servers))
	for k := range s.servers {
		keys = append(keys, k)
	}
	sort.Strings(keys) // the first server to pin a name names it
	for _, k := range keys {
		if k == server {
			continue
		}
		for name := range s.servers[k] {
			if _, ok := out[name]; !ok {
				out[name] = k
			}
		}
	}
	return out
}

// saveLocked merges this process's servers into the file on disk and
// replaces it atomically, owner-only.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f, err := readPinFile(s.path)
	if err != nil {
		return err
	}
	for k := range s.mine {
		f.Servers[k] = s.servers[k]
	}
	for k, v := range f.Servers {
		if !s.mine[k] {
			s.servers[k] = v
		}
	}
	f.Version = 1
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".mcp_pins-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	// os.CreateTemp makes the file owner-only (0600).
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

// cut shortens s to at most n bytes on a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

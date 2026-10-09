// Package runallow keeps the person's "approve for this run" answers: an
// exact request (action type and resource, e.g. http.request "POST
// https://api.example.org/v1/x" or shell "shell:make deploy") that a person
// approved once and allowed for the rest of the run. The proxy and the
// command gate consult it before opening an approval, so an identical
// request does not ask again; every use is still a receipt.
//
// The file lives in the deployment's var/ directory (only Ovara's user can
// write it, never the agent) and is emptied each time `ovara run` starts:
// an allowance never outlives the run it was given in.
package runallow

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// File is the allowance file's path inside a deployment directory.
const File = "var/run-allowances.json"

// Allowance is one request a person allowed for the rest of the run.
type Allowance struct {
	ActionType string    `json:"action_type"`
	Resource   string    `json:"resource"`
	ApprovalID string    `json:"approval_id"` // the approval it came from
	By         string    `json:"by,omitempty"`
	At         time.Time `json:"at"`
}

type file struct {
	Run   string      `json:"run"`
	Allow []Allowance `json:"allow"`
}

// Reset starts a new run with no allowances.
func Reset(path, run string) error {
	return write(path, file{Run: run, Allow: []Allowance{}})
}

// Add records an allowance for the current run.
func Add(path string, a Allowance) error {
	f, err := read(path)
	if err != nil {
		return err
	}
	for _, x := range f.Allow {
		if x.ActionType == a.ActionType && x.Resource == a.Resource {
			return nil
		}
	}
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	f.Allow = append(f.Allow, a)
	return write(path, f)
}

// Find returns the allowance for exactly this request, if there is one.
// A missing or unreadable file allows nothing.
func Find(path, actionType, resource string) (Allowance, bool) {
	f, err := read(path)
	if err != nil {
		return Allowance{}, false
	}
	for _, a := range f.Allow {
		if a.ActionType == actionType && a.Resource == resource {
			return a, true
		}
	}
	return Allowance{}, false
}

// List returns the current run's allowances.
func List(path string) []Allowance {
	f, err := read(path)
	if err != nil {
		return nil
	}
	return f.Allow
}

func read(path string) (file, error) {
	var f file
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	return f, nil
}

// write replaces the file atomically, readable by Ovara's user only.
func write(path string, f file) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".run-allowances-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

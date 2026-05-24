# Phase 7.5: Policy Distribution Service Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement real file-based policy loading with hot-reload capability, replacing the stub in LocalFileSource.

**Architecture:** Load policy from JSON file on disk. Watch file for changes using fsnotify. Allow configurable refresh interval. PolicyStore holds the current loaded policy and exposes reload capability. Version field reflects file modification time or explicit version.

**Tech Stack:** Go standard library (os, encoding/json, fsnotify), existing PolicyStore/Rule types.

---

## Task 1: Implement real JSON file-based policy loading

**Files:**
- Create: `runtime/gateway/internal/policy/file_store.go`
- Modify: `runtime/gateway/internal/policy/source.go:50-57`

**Step 1: Write the failing test**

Create `runtime/gateway/internal/policy/file_store_test.go`:

```go
package policy

import (
	"os"
	"testing"
)

func TestLoadStoreFromFile_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	policyJSON := `{
		"version": "v1-test",
		"rules": [
			{"action_type": "shell", "environment": "production", "escalate": true},
			{"action_type": "github.merge", "environment": "*", "escalate": true}
		]
	}`
	if err := os.WriteFile(policyFile, []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadStoreFromFile(policyFile, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if store.Version() != "v1-test" {
		t.Errorf("expected version v1-test, got %s", store.Version())
	}
	rules := store.RulesForAction("shell")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule for shell, got %d", len(rules))
	}
	if !rules[0].Escalate {
		t.Error("expected shell rule to escalate")
	}
}

func TestLoadStoreFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	if err := os.WriteFile(policyFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadStoreFromFile(policyFile, "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadStoreFromFile_FileNotFound(t *testing.T) {
	_, err := LoadStoreFromFile("/nonexistent/policy.json", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestLoadStoreFromFile -v`
Expected: FAIL because LoadStoreFromFile is still a stub

**Step 3: Write real implementation in file_store.go**

Create `runtime/gateway/internal/policy/file_store.go`:

```go
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

type filePolicy struct {
	Version string `json:"version"`
	Rules    []Rule `json:"rules"`
}

func LoadStoreFromFile(filePath string, versionHint string) (*Store, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var fp filePolicy
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	version := fp.Version
	if version == "" {
		version = versionHint
	}
	if version == "" {
		version = "v1-default"
	}

	store := &Store{version: version, rules: fp.Rules}
	return store, nil
}
```

**Step 4: Update source.go stub to use real implementation**

Modify `runtime/gateway/internal/policy/source.go:50-57` to call the real LoadStoreFromFile from file_store.go.

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/policy/... -run TestLoadStoreFromFile -v`
Expected: PASS

**Step 6: Run full test suite**

Run: `go test ./internal/policy/... -v`
Expected: All tests pass

**Step 7: Commit**

```bash
git add runtime/gateway/internal/policy/file_store.go runtime/gateway/internal/policy/file_store_test.go runtime/gateway/internal/policy/source.go
git commit -m "feat(policy): implement real JSON file-based policy loading"
```

---

## Task 2: Add file watching for hot-reload

**Files:**
- Create: `runtime/gateway/internal/policy/watch.go`
- Modify: `runtime/gateway/internal/policy/source.go`

**Step 1: Write the failing test**

In `file_store_test.go`, add:

```go
func TestFileWatcher_ReloadOnChange(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	initialPolicy := `{"version": "v1-initial", "rules": []}`
	if err := os.WriteFile(policyFile, []byte(initialPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadStoreFromFile(policyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if store.Version() != "v1-initial" {
		t.Fatalf("expected v1-initial, got %s", store.Version())
	}

	updatedPolicy := `{"version": "v2-updated", "rules": [{"action_type": "shell", "environment": "*", "escalate": true}]}`
	if err := os.WriteFile(policyFile, []byte(updatedPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	reloaded, err := store.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if reloaded.Version() != "v2-updated" {
		t.Errorf("expected v2-updated, got %s", reloaded.Version())
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestFileWatcher_ReloadOnChange -v`
Expected: FAIL — Store doesn't have Reload method yet

**Step 3: Add Reload method to Store**

Modify `runtime/gateway/internal/policy/store.go`, add Reload method to Store struct. Store needs a filePath field to know which file to reload from.

**Step 4: Create file watcher**

Create `runtime/gateway/internal/policy/watch.go`:

```go
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

func (w *Watcher) Reload() (*Store, error) {
	return w.source.Reload()
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/policy/... -run TestFileWatcher_ReloadOnChange -v`
Expected: PASS

**Step 6: Run full test suite**

Run: `go test ./internal/policy/... -v`
Expected: All tests pass

**Step 7: Commit**

```bash
git add runtime/gateway/internal/policy/watch.go runtime/gateway/internal/policy/store.go runtime/gateway/internal/policy/file_store_test.go
git commit -m "feat(policy): add file watcher for hot-reload"
```

---

## Task 3: Add configurable policy refresh interval

**Files:**
- Modify: `runtime/gateway/internal/config/config.go`
- Modify: `runtime/gateway/cmd/server/main.go`

**Step 1: Write the failing test**

Add test for refresh interval config:

```go
func TestConfigPolicyRefresh(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PolicyRefreshInterval != 0 {
		t.Errorf("expected default 0 (disabled), got %d", cfg.PolicyRefreshInterval)
	}

	cfg.PolicyRefreshInterval = 300 // 5 minutes
	if cfg.PolicyRefreshInterval != 300 {
		t.Errorf("expected 300, got %d", cfg.PolicyRefreshInterval)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -run TestConfigPolicyRefresh -v`
Expected: FAIL — PolicyRefreshInterval field doesn't exist

**Step 3: Add PolicyRefreshInterval to Config struct**

Modify `runtime/gateway/internal/config/config.go`, add `PolicyRefreshInterval int` field (in seconds, 0 means disabled).

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config/... -run TestConfigPolicyRefresh -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `go test ./runtime/gateway/... -v`
Expected: All tests pass

**Step 6: Commit**

```bash
git add runtime/gateway/internal/config/config.go
git commit -m "feat(config): add PolicyRefreshInterval config field"
```

---

## Task 4: Wire file watcher into server startup

**Files:**
- Modify: `runtime/gateway/cmd/server/main.go`

**Step 1: Read main.go to understand current server initialization**

**Step 2: Add file watcher initialization when LocalFileSource is configured**

In main.go, after policy store is created from file source, start the watcher if PolicyRefreshInterval > 0.

**Step 3: Run full test suite**

Run: `go build ./... && go test ./runtime/gateway/...`
Expected: All pass

**Step 4: Commit**

```bash
git add runtime/gateway/cmd/server/main.go
git commit -m "feat(server): wire file watcher for hot-reload on startup"
```

---

## Task 5: Update documentation

**Files:**
- Modify: `docs/developer/runtime_examples.md`

**Step 1: Add section on file-based policy loading**

Document:
- JSON schema for policy files
- How to configure LocalFileSource
- Hot-reload behavior
- PolicyRefreshInterval config

**Step 2: Run tests**

Run: `go build ./... && go test ./...`
Expected: All pass

**Step 3: Commit**

```bash
git add docs/developer/runtime_examples.md
git commit -m "docs: document file-based policy loading and hot-reload"
```

---

## Execution Options

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
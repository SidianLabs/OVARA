// Package sandbox is the sandbox runtime interface, contract C5 of the
// specification (spec/runtime.md): the manifest that describes one run, the
// events a run emits while it happens, and the summary it ends with. The
// JSON Schemas next to the specification (spec/schemas/manifest.schema.json,
// event.schema.json) name exactly these members.
//
// `ovara box` is the reference runtime: it reads a manifest (-manifest),
// writes the one its flags describe (-print-manifest) and streams events
// (-events). A manifest says nothing secret: credentials stay in Ovara's
// deployment, and a variable whose name says it is a key is refused.
package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Version is the manifest format this package reads and writes.
const Version = "0.1"

// Manifest describes one sandbox run.
type Manifest struct {
	// Version of the manifest format: "0.1".
	Version string `json:"version"`
	// Tier is the isolation: 1 (separate user, network namespace, own root
	// file system) or 2 (a container). The default is 1.
	Tier int `json:"tier,omitempty"`
	// Workspace is the project the agent works on a copy of.
	Workspace Workspace `json:"workspace"`
	// Agent is the command to run and how it is named.
	Agent Agent `json:"agent"`
	// Deployment is Ovara's own directory for this run (policy.json,
	// proxy.json, keys); empty means the default (~/.ovara/box).
	Deployment string `json:"deployment,omitempty"`
	// Profile is "dev" (installs are free), "strict" (a dependency not in
	// the project's lockfiles pauses once) or "ci" (strict, and whatever
	// would pause is refused at once: no one answers). The default is "dev".
	Profile string `json:"profile,omitempty"`
	// UntrustedLockfiles, with the strict profile, trusts nothing the
	// project's lockfiles pin (a repository under review, not one's own).
	UntrustedLockfiles bool `json:"untrusted_lockfiles,omitempty"`
	// Isolation holds the tier's own settings.
	Isolation Isolation `json:"isolation,omitempty"`
	// Mounts are host paths mounted read-only into the box, as "SRC:DST".
	Mounts []string `json:"mounts,omitempty"`
	// Limits bound the box (tier 2).
	Limits Limits `json:"limits,omitempty"`
	// Credentials says how Ovara's credentials are scoped for this run.
	Credentials Credentials `json:"credentials,omitempty"`
	// CommitBack says how changes come back.
	CommitBack CommitBack `json:"commit_back,omitempty"`
	// CommandGate false runs the agent without the check on every program
	// it starts (the network and file boundaries still hold). Absent means
	// true.
	CommandGate *bool `json:"command_gate,omitempty"`
	// UI is the approval page address (loopback only) or "off"; empty
	// means the default.
	UI string `json:"ui,omitempty"`
}

// Workspace is the project copied into the box.
type Workspace struct {
	// Source is the project directory on the host (a git repository).
	Source string `json:"source"`
	// Exclude are extra path globs left out of the copy (.ovaraignore is
	// read too).
	Exclude []string `json:"exclude,omitempty"`
}

// Agent is the command that runs inside.
type Agent struct {
	// Name is the named agent the run is attributed to (its own proxy
	// token); empty means the deployment's default agent.
	Name string `json:"name,omitempty"`
	// Command is the agent's command line, program first.
	Command []string `json:"command"`
	// Env are extra variables for the agent. Values that look like keys
	// are refused: real keys stay with Ovara.
	Env map[string]string `json:"env,omitempty"`
}

// Isolation holds the per-tier settings.
type Isolation struct {
	// Name is the tier 1 network namespace name (one box per name).
	Name string `json:"name,omitempty"`
	// User is the unprivileged user the agent runs as in tier 1.
	User string `json:"user,omitempty"`
	// RootFS is "isolated" (a root file system of its own; the default) or
	// "host" (the host's, where the agent reads what its user may: unsafe
	// on a machine with secrets), tier 1.
	RootFS string `json:"root_fs,omitempty"`
	// AllowVisibleProcs starts a tier 1 box on a kernel that cannot hide
	// other users' processes from it.
	AllowVisibleProcs bool `json:"allow_visible_procs,omitempty"`
	// Image is the tier 2 box image.
	Image string `json:"image,omitempty"`
}

// Limits bound a tier 2 box.
type Limits struct {
	PIDs   int    `json:"pids,omitempty"`
	Memory string `json:"memory,omitempty"` // docker syntax, e.g. "8g"
	CPUs   string `json:"cpus,omitempty"`   // e.g. "2"
}

// Credentials says how Ovara's credentials are scoped for the run.
type Credentials struct {
	// GitHubScope is "repo" (the GitHub key only goes with requests about
	// the project's own repository; the default) or "all".
	GitHubScope string `json:"github_scope,omitempty"`
}

// CommitBack says how changes come back from the box.
type CommitBack struct {
	// Disabled leaves the changes in the workspace; nothing is offered.
	Disabled bool `json:"disabled,omitempty"`
	// AllowBinary lets binary files the agent added or changed come back.
	AllowBinary bool `json:"allow_binary,omitempty"`
	// ApproveTimeout is how long the commit-back waits for a person, as a
	// Go duration ("10m"); empty means the default.
	ApproveTimeout string `json:"approve_timeout,omitempty"`
	// KeepWorkspace keeps the workspace after the run whatever happened.
	KeepWorkspace bool `json:"keep_workspace,omitempty"`
}

// Values the validator accepts.
const (
	ProfileDev     = "dev"
	ProfileStrict  = "strict"
	ProfileCI      = "ci"
	RootFSIsolated = "isolated"
	RootFSHost     = "host"
	ScopeRepo      = "repo"
	ScopeAll       = "all"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// KeyLikeName matches an environment variable name that would carry a
// credential into the box. `ovara box -env` and a manifest's agent.env
// refuse such a name, whatever the value: real keys stay in Ovara's
// environment and are injected on the way out.
var KeyLikeName = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)

// Load reads and validates a manifest file.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Parse reads and validates a manifest. Unknown members are refused: a
// misspelt member must not silently mean the default.
func Parse(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("more than one JSON value")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate reports the first thing wrong with m.
func (m *Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("version %q: this build reads %q", m.Version, Version)
	}
	switch m.Tier {
	case 0, 1, 2:
	default:
		return fmt.Errorf("tier %d: want 1 or 2", m.Tier)
	}
	if strings.TrimSpace(m.Workspace.Source) == "" {
		return errors.New("workspace.source is required: the project directory")
	}
	if len(m.Agent.Command) == 0 || strings.TrimSpace(m.Agent.Command[0]) == "" {
		return errors.New("agent.command is required: the program to run, then its arguments")
	}
	for k := range m.Agent.Env {
		if !envName.MatchString(k) {
			return fmt.Errorf("agent.env %q: not a variable name", k)
		}
		if KeyLikeName.MatchString(k) {
			return fmt.Errorf("agent.env %s: looks like a secret; put real keys in Ovara's environment (proxy.json credentials), never in the box", k)
		}
	}
	switch m.Profile {
	case "", ProfileDev, ProfileStrict, ProfileCI:
	default:
		return fmt.Errorf("profile %q: want %q, %q or %q", m.Profile, ProfileDev, ProfileStrict, ProfileCI)
	}
	if m.UntrustedLockfiles && m.Profile != ProfileStrict && m.Profile != ProfileCI {
		return errors.New("untrusted_lockfiles is for the strict profile, or ci (the dev profile asks about no package)")
	}
	switch m.Isolation.RootFS {
	case "", RootFSIsolated, RootFSHost:
	default:
		return fmt.Errorf("isolation.root_fs %q: want %q or %q", m.Isolation.RootFS, RootFSIsolated, RootFSHost)
	}
	if m.Isolation.RootFS == RootFSHost && len(m.Mounts) > 0 {
		return errors.New("mounts need a box file system: with isolation.root_fs \"host\" the agent already sees the host's files its user may read")
	}
	for _, mnt := range m.Mounts {
		src, dst, ok := strings.Cut(mnt, ":")
		if !ok || src == "" || dst == "" {
			return fmt.Errorf("mounts %q: want SRC:DST", mnt)
		}
	}
	if m.Limits.PIDs < 0 {
		return fmt.Errorf("limits.pids %d: want 0 (default) or more", m.Limits.PIDs)
	}
	switch m.Credentials.GitHubScope {
	case "", ScopeRepo, ScopeAll:
	default:
		return fmt.Errorf("credentials.github_scope %q: want %q or %q", m.Credentials.GitHubScope, ScopeRepo, ScopeAll)
	}
	if t := m.CommitBack.ApproveTimeout; t != "" {
		if d, err := time.ParseDuration(t); err != nil || d <= 0 {
			return fmt.Errorf("commit_back.approve_timeout %q: want a duration such as \"10m\"", t)
		}
	}
	return nil
}

// Encode writes m as indented JSON, the form `ovara box -print-manifest`
// prints.
func (m *Manifest) Encode() ([]byte, error) {
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

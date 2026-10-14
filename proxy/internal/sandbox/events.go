package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventVersion is the events stream format this package writes.
const EventVersion = 1

// The events a run emits, in the order they can happen. A tool driving the
// box reads them as JSON lines (`ovara box -events FILE`).
const (
	EventRunCreated      = "run.created"      // the run exists; Manifest is the run written down
	EventWorkspaceCopied = "workspace.copied" // the project's copy is in place (Workspace)
	EventProxyStarted    = "proxy.started"    // Ovara is up for this run
	EventAgentStarted    = "agent.started"    // the agent is running (Command)

	EventCommandAllowed     = "command.allowed"      // a program the agent started, allowed by policy (Command)
	EventCommandRefused     = "command.refused"      // ... refused by policy, or the gateway could not be asked
	EventCommandPaused      = "command.paused"       // ... waiting for a person (ApprovalID)
	EventCommandApproved    = "command.approved"     // ... approved, so it runs (ApprovalID)
	EventCommandNotApproved = "command.not_approved" // ... not run; Status says denied, expired or timed out

	EventAgentExited = "agent.exited" // Code is the agent's exit status

	EventCommitBackDisabled    = "commit_back.disabled"     // nothing is offered (-no-commit-back)
	EventCommitBackNothing     = "commit_back.nothing"      // the agent changed nothing
	EventCommitBackKept        = "commit_back.kept"         // every changed path is kept out
	EventCommitBackRefused     = "commit_back.refused"      // policy refuses the commit-back
	EventCommitBackWaiting     = "commit_back.waiting"      // waiting for a person (ApprovalID, Files)
	EventCommitBackNotApproved = "commit_back.not_approved" // Status says denied, expired or timed out
	EventCommitBackLanded      = "commit_back.landed"       // Branch, Commit, Files

	EventRunFinished = "run.finished" // Summary; Error when the run failed
)

// Outcomes of a run (Summary.Outcome).
const (
	OutcomeClean  = "clean"  // the agent ran, and whatever came back is on its branch
	OutcomeKept   = "kept"   // the run ended with the workspace kept for a person
	OutcomeFailed = "failed" // the launcher could not finish the run
)

// Event is one line of the events stream. The members after Event are
// filled by the events that use them (see the constants) and omitted
// otherwise.
type Event struct {
	V     int    `json:"v"`      // EventVersion
	Time  string `json:"time"`   // RFC 3339, UTC
	RunID string `json:"run_id"` // the run the event belongs to
	Event string `json:"event"`

	Manifest   *Manifest `json:"manifest,omitempty"`
	Workspace  string    `json:"workspace,omitempty"`
	Command    string    `json:"command,omitempty"`
	ApprovalID string    `json:"approval_id,omitempty"`
	Status     string    `json:"status,omitempty"`
	Code       *int      `json:"code,omitempty"`
	Files      int       `json:"files,omitempty"`
	Branch     string    `json:"branch,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Error      string    `json:"error,omitempty"`
	Summary    *Summary  `json:"summary,omitempty"`
}

// Summary is how a run ended: the last event's payload, and what the
// launcher prints on its last lines.
type Summary struct {
	Outcome  string  `json:"outcome"`            // OutcomeClean, OutcomeKept or OutcomeFailed
	ExitCode int     `json:"exit_code"`          // the agent's
	Requests Counts  `json:"requests"`           // through the proxy during the run
	Hosts    int     `json:"hosts"`              // distinct hosts requested
	Commands *Counts `json:"commands,omitempty"` // through the command gate; absent when the gate was off
	// CommitBack is how the changes ended: the commit_back event's name
	// after the dot (disabled, nothing, kept, refused, not_approved,
	// landed), or empty when the run failed before that.
	CommitBack string `json:"commit_back"`
	Branch     string `json:"branch,omitempty"`
	Commit     string `json:"commit,omitempty"`
	// Attestation is where the run's signed statement was written, relative
	// to the deployment (var/attestations/<run>.intoto.json; spec C4 §8).
	Attestation string `json:"attestation,omitempty"`
}

// Counts tallies decisions.
type Counts struct {
	Allowed  int `json:"allowed"`
	Paused   int `json:"paused"`   // requests: held for a person; commands: waited for one
	Approved int `json:"approved"` // commands a person approved
	Denied   int `json:"denied"`
}

// Events writes the stream: one JSON line per event, written as it
// happens. A nil *Events writes nothing, so a run without -events pays
// nothing for the calls.
type Events struct {
	mu    sync.Mutex
	w     io.Writer
	c     io.Closer
	runID string
	now   func() time.Time
}

// OpenEvents appends the stream to the file at path, created 0600 when it
// does not exist. Runs can share a file: run_id tells them apart. A
// symbolic link is refused: the launcher writes as root, and the link
// could point anywhere.
func OpenEvents(path, runID string) (*Events, error) {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link; the events stream is written to a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the path the person gave for the stream
	if err != nil {
		return nil, err
	}
	return &Events{w: f, c: f, runID: runID, now: time.Now}, nil
}

// NewEvents writes the stream to w.
func NewEvents(w io.Writer, runID string) *Events {
	return &Events{w: w, runID: runID, now: time.Now}
}

// Emit writes ev with the version, time and run id filled in.
func (e *Events) Emit(ev Event) {
	if e == nil {
		return
	}
	ev.V = EventVersion
	ev.RunID = e.runID
	ev.Time = e.now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.w.Write(append(b, '\n'))
}

// Close closes the file behind OpenEvents.
func (e *Events) Close() error {
	if e == nil || e.c == nil {
		return nil
	}
	return e.c.Close()
}

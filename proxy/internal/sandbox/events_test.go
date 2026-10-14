package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventsAreJSONLinesWithTheFixedMembers(t *testing.T) {
	var buf bytes.Buffer
	ev := NewEvents(&buf, "run-1")
	ev.now = func() time.Time { return time.Date(2026, 10, 14, 1, 2, 3, 4000, time.UTC) }
	code := 3
	m, err := Parse([]byte(valid()))
	if err != nil {
		t.Fatal(err)
	}
	ev.Emit(Event{Event: EventRunCreated, Manifest: m})
	ev.Emit(Event{Event: EventCommandPaused, Command: "rm -rf /tmp/victim", ApprovalID: "apr_1"})
	ev.Emit(Event{Event: EventAgentExited, Code: &code})
	ev.Emit(Event{Event: EventRunFinished, Summary: &Summary{Outcome: OutcomeClean, ExitCode: 3, Requests: Counts{Allowed: 2}, Hosts: 1, CommitBack: "landed", Branch: "ovara/box-1", Commit: "abc"}})

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines:\n%s", len(lines), buf.String())
	}
	got := make([]map[string]any, 0, len(lines))
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		if m["v"] != float64(EventVersion) || m["run_id"] != "run-1" || m["time"] != "2026-10-14T01:02:03.000004Z" {
			t.Fatalf("fixed members: %s", l)
		}
		got = append(got, m)
	}
	if got[0]["event"] != EventRunCreated || got[0]["manifest"].(map[string]any)["version"] != Version {
		t.Errorf("run.created: %v", got[0])
	}
	if _, ok := got[0]["code"]; ok {
		t.Errorf("code is written only when set: %v", got[0])
	}
	if got[1]["approval_id"] != "apr_1" || got[1]["command"] != "rm -rf /tmp/victim" {
		t.Errorf("command.paused: %v", got[1])
	}
	if got[2]["code"] != float64(3) {
		t.Errorf("agent.exited: %v", got[2])
	}
	s := got[3]["summary"].(map[string]any)
	if s["outcome"] != OutcomeClean || s["commit_back"] != "landed" || s["requests"].(map[string]any)["allowed"] != float64(2) {
		t.Errorf("run.finished: %v", got[3])
	}
	if _, ok := s["commands"]; ok {
		t.Errorf("commands is absent when the gate was off: %v", s)
	}
}

func TestNilEventsWriteNothing(t *testing.T) {
	var ev *Events
	ev.Emit(Event{Event: EventRunFinished}) // must not panic
	if err := ev.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenEventsAppendsToAnOwnerOnlyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	for _, run := range []string{"a", "b"} {
		ev, err := OpenEvents(p, run)
		if err != nil {
			t.Fatal(err)
		}
		ev.Emit(Event{Event: EventRunCreated})
		if err := ev.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 || !strings.Contains(string(b), `"run_id":"a"`) || !strings.Contains(string(b), `"run_id":"b"`) {
		t.Fatalf("two runs, one file:\n%s", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	// a symbolic link in the way is refused, whatever it points at
	link := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.Symlink(p, link); err != nil {
		t.Skip(err)
	}
	if _, err := OpenEvents(link, "c"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink: %v", err)
	}
}

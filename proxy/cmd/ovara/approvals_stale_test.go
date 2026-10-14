package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// With the retry answer (what `ovara init` writes), a request the proxy
// has stopped holding is still worth approving: the agent sends it again
// and it runs. So no approval is hidden as "the agent already stopped
// waiting". With the older timeout answer, approvals older than the hold
// are hidden as before.
func TestApprovalsAreNotHiddenUnderTheRetryAnswer(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	c, err := newAdminClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := pendingApproval{ActionType: "http.request", CreatedAt: time.Now().Add(-time.Hour)}
	if c.maxWait != 0 || c.stale(old) {
		t.Fatalf("retry answer: maxWait=%v stale=%v, want 0 and false", c.maxWait, c.stale(old))
	}
	// The older behaviour, chosen in proxy.json.
	p := filepath.Join(dir, "proxy.json")
	raw, _ := os.ReadFile(p)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["escalate_on_timeout"] = "timeout"
	doc["escalate_timeout_sec"] = 60
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = newAdminClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.maxWait != 60*time.Second || !c.stale(old) {
		t.Fatalf("timeout answer: maxWait=%v stale=%v, want 60s and true", c.maxWait, c.stale(old))
	}
}

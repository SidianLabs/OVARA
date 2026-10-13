package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

func initDeployment(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ASI03/ASI07: `ovara agent add` gives an agent its own 32-byte token in
// the owner-only proxy.json without printing it; `ovara env -agent` hands
// that agent its proxy URL; list shows names and state, never tokens;
// remove takes the token away.
func TestAgentAddListEnvRemove(t *testing.T) {
	dir := initDeployment(t)
	var out bytes.Buffer
	if err := agentAdd(&out, dir, "ci-bot"); err != nil {
		t.Fatal(err)
	}
	agents, legacy, err := config.ReadAgents(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	tok := agents["ci-bot"]
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(tok) {
		t.Fatalf("token %q", tok)
	}
	if strings.Contains(out.String(), tok) {
		t.Fatal("agent add printed the token")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, "proxy.json")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("proxy.json mode %v", fi.Mode().Perm())
		}
	}
	if err := agentAdd(&out, dir, "ci-bot"); err == nil {
		t.Fatal("added the same agent twice")
	}
	for _, bad := range []string{"Bad", "default", ""} {
		if err := agentAdd(&out, dir, bad); err == nil {
			t.Fatalf("agent name %q accepted", bad)
		}
	}

	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentToken != legacy {
		t.Fatal("agent add changed agent_token")
	}
	pt, err := agentProxyToken(cfg, "ci-bot")
	if err != nil || pt != tok {
		t.Fatalf("env token %q %v", pt, err)
	}
	cfg.AgentToken = pt
	vars, _, err := agentEnv(dir, cfg, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if vars[0].name != "HTTPS_PROXY" || vars[0].value != "http://agent:"+tok+"@127.0.0.1:9443" {
		t.Fatalf("HTTPS_PROXY %+v", vars[0])
	}
	if _, err := agentProxyToken(cfg, "nobody"); err == nil {
		t.Fatal("env for an unknown agent")
	}

	out.Reset()
	if err := agentList(&out, dir); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ci-bot") || !strings.Contains(out.String(), "default") || strings.Contains(out.String(), tok) || strings.Contains(out.String(), legacy) {
		t.Fatalf("list:\n%s", out.String())
	}

	if err := agentRemove(&out, dir, "ci-bot"); err != nil {
		t.Fatal(err)
	}
	if agents, _, _ := config.ReadAgents(filepath.Join(dir, "proxy.json")); len(agents) != 0 {
		t.Fatalf("after remove: %v", agents)
	}
	if err := agentRemove(&out, dir, "ci-bot"); err == nil {
		t.Fatal("removed an agent that is not there")
	}
}

// `ovara init -agents a,b` creates the named agents with the deployment.
func TestInitCreatesNamedAgents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := cmdInit([]string{dir, "-agents", "alpha, beta"}); err != nil {
		t.Fatal(err)
	}
	agents, legacy, err := config.ReadAgents(filepath.Join(dir, "proxy.json"))
	if err != nil || len(agents) != 2 || agents["alpha"] == "" || agents["beta"] == "" || legacy == "" {
		t.Fatalf("agents %v legacy set %v err %v", agents, legacy != "", err)
	}
}

// ASI10: `ovara kill -agent NAME` writes the stopped list (owner-only),
// denies only that agent's waiting requests, and `ovara agent restore`
// undoes it; without -agent every agent is stopped and everything
// waiting is denied.
func TestKillStopsOneAgentAndDeniesItsApprovals(t *testing.T) {
	dir := initDeployment(t)
	var out bytes.Buffer
	for _, n := range []string{"ci", "rev"} {
		if err := agentAdd(&out, dir, n); err != nil {
			t.Fatal(err)
		}
	}
	f, c := newFake(t,
		pendingApproval{ApprovalID: "a1", Resource: "POST https://x/1", Context: map[string]string{"agent": "ci"}},
		pendingApproval{ApprovalID: "a2", Resource: "POST https://x/2", Context: map[string]string{"agent": "rev"}},
		pendingApproval{ApprovalID: "a3", Resource: "shell:rm -rf /"})
	admin := func() (*adminClient, error) { return c, nil }

	if err := kill(&out, dir, "nobody", admin); err == nil {
		t.Fatal("killed an unknown agent")
	}
	if err := kill(&out, dir, "ci", admin); err != nil {
		t.Fatal(err)
	}
	rp := filepath.Join(dir, "var", "revoked_agents.json")
	rv, err := config.LoadRevoked(rp)
	if err != nil || len(rv.Stopped) != 1 || rv.Stopped["ci"].IsZero() {
		t.Fatalf("stopped %+v %v", rv, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(rp); fi.Mode().Perm() != 0o600 {
			t.Fatalf("revoked file mode %v", fi.Mode().Perm())
		}
	}
	f.mu.Lock()
	if len(f.resolved) != 1 || f.resolved["a1"] != "deny" {
		t.Fatalf("resolved %v", f.resolved)
	}
	f.mu.Unlock()
	if !strings.Contains(out.String(), "denied 1 request") {
		t.Fatalf("output:\n%s", out.String())
	}
	out.Reset()
	if err := agentList(&out, dir); err != nil || !strings.Contains(out.String(), "STOPPED") {
		t.Fatalf("list after kill: %v\n%s", err, out.String())
	}

	if err := agentRestore(&out, dir, "ci"); err != nil {
		t.Fatal(err)
	}
	if rv, _ := config.LoadRevoked(rp); len(rv.Stopped) != 0 {
		t.Fatalf("after restore %+v", rv)
	}
	if err := agentRestore(&out, dir, "ci"); err == nil {
		t.Fatal("restored an agent that was not stopped")
	}

	if err := kill(&out, dir, "", admin); err != nil {
		t.Fatal(err)
	}
	if rv, _ := config.LoadRevoked(rp); !rv.Stopped[config.AllAgents].After(rv.Stopped["x"]) {
		t.Fatalf("kill without -agent: %+v", rv)
	}
	f.mu.Lock()
	if len(f.resolved) != 3 {
		t.Fatalf("kill all resolved %v", f.resolved)
	}
	f.mu.Unlock()
	if err := agentRestore(&out, dir, config.AllAgents); err != nil {
		t.Fatal(err)
	}
}

// The stop is written even when the gateway cannot be reached.
func TestKillWithoutGatewayStillStops(t *testing.T) {
	dir := initDeployment(t)
	var out bytes.Buffer
	if err := kill(&out, dir, "default", func() (*adminClient, error) { return nil, errors.New("down") }); err != nil {
		t.Fatal(err)
	}
	rv, err := config.LoadRevoked(filepath.Join(dir, "var", "revoked_agents.json"))
	if err != nil || rv.Stopped["default"].IsZero() {
		t.Fatalf("%+v %v", rv, err)
	}
	if !strings.Contains(out.String(), "not denied") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// ASI01/ASI08: the default policy pauses tainted writes and model use past
// its budget.
func TestDefaultPolicy_TaintAndModelBudgetEscalate(t *testing.T) {
	if got := defaultDecision("taint.write", "taint:POST https://api.github.com/repos/o/r/pulls"); got != "escalate" {
		t.Fatalf("taint.write: %s", got)
	}
	if got := defaultDecision("model.budget", "model-budget:api.anthropic.com"); got != "escalate" {
		t.Fatalf("model.budget: %s", got)
	}
}

// The approver sees which agent asks and why a taint question is asked.
func TestApprovalShowsAgentNameAndTaint(t *testing.T) {
	a := pendingApproval{ApprovalID: "x", AgentID: "ag_123", Resource: "taint:POST https://api.github.com:443/repos/o/r/pulls",
		Context: map[string]string{"agent": "ci", "taint": "the agent read untrusted content from https://github.com/o/r/issues/1 2m0s ago"}}
	var out bytes.Buffer
	printApproval(&out, a)
	s := out.String()
	if !strings.Contains(s, "agent:          ci") || strings.Contains(s, "ag_123") {
		t.Fatalf("agent line:\n%s", s)
	}
	if !strings.Contains(s, "untrusted input: the agent read untrusted content from https://github.com/o/r/issues/1") {
		t.Fatalf("taint line:\n%s", s)
	}
	if got := describe(a.Resource); got != "send data to https://api.github.com/repos/o/r/pulls (soon after reading untrusted content)" {
		t.Fatalf("describe: %q", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRememberOptions(t *testing.T) {
	cases := []struct {
		a    pendingApproval
		want []string
	}{
		{pendingApproval{ActionType: "http.request", Resource: "GET https://docs.example.com/x"}, []string{scopeReadsRun, scopeReadsProject}},
		{pendingApproval{ActionType: "http.request", Resource: "HEAD https://docs.example.com/"}, []string{scopeReadsRun, scopeReadsProject}},
		{pendingApproval{ActionType: "http.request", Resource: "POST https://docs.example.com/x"}, nil},
		{pendingApproval{ActionType: "http.request", Resource: "GET http://docs.example.com/x"}, nil},
		{pendingApproval{ActionType: "http.request", Resource: "GET https://10.0.0.5/x"}, nil},
		{pendingApproval{ActionType: "shell", Resource: "shell:rm -rf /tmp/x"}, []string{scopeCommandRun}},
		{pendingApproval{ActionType: "shell", Resource: "shell:rm -rf *"}, nil},
		{pendingApproval{ActionType: "shell", Resource: "shell:"}, nil},
		{pendingApproval{ActionType: "mcp.tool_call", Resource: "mcp:stdio:fake/send_email"}, []string{scopeToolRun}},
		{pendingApproval{ActionType: "mcp.tool_call", Resource: "mcp:mcp.example.com/mcp/*"}, nil},
		{pendingApproval{ActionType: "fs.commit_back", Resource: "commit:x"}, nil},
		{pendingApproval{ActionType: "taint.write", Resource: "taint:POST https://x/y"}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, o := range rememberOptions(c.a) {
			got = append(got, o.Key)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s: %v, want %v", c.a.ActionType, c.a.Resource, got, c.want)
		}
	}
}

// Each remembered rule is exact, says who, when and from which approval,
// and a run-scoped one goes with the run while a project one stays.
func TestRemember_ScopesAndTheRun(t *testing.T) {
	dir := t.TempDir()
	orig := `{"version":"v1","rules":[{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	read := pendingApproval{ApprovalID: "apr_1", ActionType: "http.request", Resource: "GET https://docs.example.com/x"}
	cmd := pendingApproval{ApprovalID: "apr_2", ActionType: "shell", Resource: "shell:rm -rf /tmp/x"}
	tool := pendingApproval{ApprovalID: "apr_3", ActionType: "mcp.tool_call", Resource: "mcp:stdio:fake/send_email"}
	for _, c := range []struct {
		a     pendingApproval
		scope string
		who   string
	}{{read, scopeReadsProject, "ann"}, {cmd, scopeCommandRun, "ann"}, {tool, scopeToolRun, ""}} {
		if added, err := remember(dir, c.a, c.scope, c.who); err != nil || !added {
			t.Fatalf("%s: added=%v err=%v", c.scope, added, err)
		}
	}
	if added, err := remember(dir, cmd, scopeCommandRun, "ann"); err != nil || added {
		t.Fatalf("the same command twice: added=%v err=%v", added, err)
	}
	if _, err := remember(dir, pendingApproval{ActionType: "http.request", Resource: "POST https://x.example/y"}, scopeReadsRun, "ann"); err == nil || !strings.Contains(err.Error(), "cannot be remembered") {
		t.Fatalf("a write: %v", err)
	}
	if _, err := remember(dir, read, scopeCommandRun, "ann"); err == nil {
		t.Fatal("a read remembered as a command")
	}
	_, rules, err := readPolicyDoc(dir)
	if err != nil || len(rules) != 5 {
		t.Fatalf("%v, %d rules", err, len(rules))
	}
	day := time.Now().Format("2006-01-02")
	byRes := map[string]map[string]any{}
	for _, r := range rules {
		rm := r.(map[string]any)
		byRes[rm["resource"].(string)] = rm
	}
	c := byRes["shell:rm -rf /tmp/x"]
	if c["action_type"] != "shell" || c["allow"] != true {
		t.Fatalf("command rule: %v", c)
	}
	for _, want := range []string{runTrustMarker, " by ann", "approval apr_2", day} {
		if d := c["description"].(string); !strings.Contains(d, want) {
			t.Errorf("command description %q lacks %q", d, want)
		}
	}
	tl := byRes["mcp:stdio:fake/send_email"]
	if d := tl["description"].(string); tl["action_type"] != "mcp.tool_call" || !strings.HasPrefix(d, runTrustMarker) || strings.Contains(d, " by ") || !strings.Contains(d, "approval apr_3") {
		t.Fatalf("tool rule: %v", tl)
	}
	rd := byRes["GET https://docs.example.com/*"]
	if d := rd["description"].(string); !strings.HasPrefix(d, projectMarker) || !strings.Contains(d, " by ann") || !strings.Contains(d, "approval apr_1") || strings.Contains(d, runTrustMarker) {
		t.Fatalf("project rule: %v", rd)
	}
	if _, ok := byRes["HEAD https://docs.example.com/*"]; !ok {
		t.Fatal("HEAD missing")
	}

	what, err := dropRunTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(what)
	if !reflect.DeepEqual(what, []string{"command `rm -rf /tmp/x`", "tool mcp:stdio:fake/send_email"}) {
		t.Fatalf("dropped %v", what)
	}
	if _, rules, _ := readPolicyDoc(dir); len(rules) != 3 {
		t.Fatalf("after the run: %v", rules)
	}
	if got := describeRemembered([]string{"docs.example.com", "command `x`"}); got != "reads from docs.example.com, command `x`" {
		t.Fatalf("describeRemembered: %q", got)
	}
}

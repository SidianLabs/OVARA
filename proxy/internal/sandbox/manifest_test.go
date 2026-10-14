package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func valid() string {
	return `{"version":"0.1","tier":2,"workspace":{"source":"/srv/app","exclude":["dist/*"]},
	 "agent":{"name":"reviewer","command":["opencode","run","fix the tests"],"env":{"CI":"1"}},
	 "profile":"strict","isolation":{"image":"ghcr.io/x/box@sha256:abc"},"mounts":["/opt/tools:/opt/tools"],
	 "limits":{"pids":2048,"memory":"8g","cpus":"2"},"credentials":{"github_scope":"repo"},
	 "commit_back":{"allow_binary":false,"approve_timeout":"15m"},"command_gate":true,"ui":"off"}`
}

func TestParseValidManifest(t *testing.T) {
	m, err := Parse([]byte(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if m.Tier != 2 || m.Workspace.Source != "/srv/app" || m.Agent.Command[0] != "opencode" || m.Profile != ProfileStrict || m.Limits.PIDs != 2048 || m.CommitBack.ApproveTimeout != "15m" {
		t.Fatalf("%+v", m)
	}
	out, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(out)
	if err != nil || !reflect.DeepEqual(again, m) {
		t.Fatalf("round trip: %v\n%s", err, out)
	}
}

// Everything the validator refuses, with the reason a person reads.
func TestParseRefusals(t *testing.T) {
	edit := func(f func(m map[string]any)) string {
		var m map[string]any
		_ = json.Unmarshal([]byte(valid()), &m)
		f(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	cases := map[string]struct {
		in   string
		want string
	}{
		"unknown member": {strings.Replace(valid(), `"tier":2`, `"tier":2,"tire":1`, 1), "unknown field"},
		"wrong version":  {edit(func(m map[string]any) { m["version"] = "9" }), "version"},
		"bad tier":       {edit(func(m map[string]any) { m["tier"] = 3 }), "tier 3"},
		"no source":      {edit(func(m map[string]any) { m["workspace"] = map[string]any{} }), "workspace.source"},
		"no command":     {edit(func(m map[string]any) { m["agent"] = map[string]any{"command": []string{}} }), "agent.command"},
		"secret in env": {edit(func(m map[string]any) {
			m["agent"] = map[string]any{"command": []string{"x"}, "env": map[string]string{"OPENAI_API_KEY": "sk-live"}}
		}), "looks like a secret"},
		"bad env name": {edit(func(m map[string]any) {
			m["agent"] = map[string]any{"command": []string{"x"}, "env": map[string]string{"1BAD": "x"}}
		}), "not a variable name"},
		"bad profile":      {edit(func(m map[string]any) { m["profile"] = "lax" }), "profile"},
		"untrusted on dev": {edit(func(m map[string]any) { m["profile"] = "dev"; m["untrusted_lockfiles"] = true }), "strict profile"},
		"bad root fs":      {edit(func(m map[string]any) { m["isolation"] = map[string]any{"root_fs": "shared"} }), "root_fs"},
		"mount on host fs": {edit(func(m map[string]any) { m["isolation"] = map[string]any{"root_fs": "host"} }), "mounts need a box file system"},
		"bad mount":        {edit(func(m map[string]any) { m["mounts"] = []string{"/only-src"} }), "SRC:DST"},
		"negative pids":    {edit(func(m map[string]any) { m["limits"] = map[string]any{"pids": -1} }), "limits.pids"},
		"bad scope":        {edit(func(m map[string]any) { m["credentials"] = map[string]any{"github_scope": "org"} }), "github_scope"},
		"bad timeout":      {edit(func(m map[string]any) { m["commit_back"] = map[string]any{"approve_timeout": "soon"} }), "approve_timeout"},
		"two documents":    {valid() + valid(), "more than one"},
		"key name, no value": {edit(func(m map[string]any) {
			m["agent"] = map[string]any{"command": []string{"x"}, "env": map[string]string{"GITHUB_TOKEN": ""}}
		}), "looks like a secret"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestLoadReadsAFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sandbox.json")
	if err := os.WriteFile(p, []byte(valid()), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, err := Load(p); err != nil || m.Agent.Name != "reviewer" {
		t.Fatalf("%v %+v", err, m)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file: want an error")
	}
}

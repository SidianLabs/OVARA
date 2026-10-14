package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/sandbox"
)

func TestBoxArgs_FlagsAndPositional(t *testing.T) {
	o, x, err := parseBoxArgs([]string{"-tier", "2", "-image", "img", "-env", "CI=1", "-mount", "/a:/b", "-events", "ev.jsonl", "./proj", "--", "bash", "-c", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if o.tier != 2 || o.image != "img" || !reflect.DeepEqual([]string(o.envs), []string{"CI=1"}) || !reflect.DeepEqual([]string(o.mounts), []string{"/a:/b"}) ||
		o.project != "./proj" || !reflect.DeepEqual(o.cmd, []string{"bash", "-c", "x"}) || x.events != "ev.jsonl" || x.printManifest {
		t.Fatalf("%+v %+v", o, x)
	}
	// the defaults a bare command line gets
	if o.user != boxDefaultUser || o.profile != boxProfileDev || o.approveTimeout != 10*time.Minute || o.ghScope != "repo" || o.noGate {
		t.Fatalf("defaults: %+v", o)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"./proj"}, "need a project directory, then --, then the agent command"},
		{[]string{"./proj", "--"}, "want: <project-dir> -- <agent command...>"},
		{[]string{"./proj", "bash"}, "want: <project-dir> -- <agent command...>"},
		{[]string{"--", "bash"}, "need a project directory"},
		{[]string{"-tier", "3", "./proj", "--", "x"}, "-tier 3: want 1 or 2"},
		{[]string{"-env", "API_KEY=x", "./proj", "--", "x"}, "looks like a secret"},
		{[]string{"-env", "CI", "./proj", "--", "x"}, "want NAME=value"},
		{[]string{"-untrusted-lockfiles", "./proj", "--", "x"}, "is for -profile strict"},
		{[]string{"-tier1-fs", "host", "-mount", "/a:/b", "./proj", "--", "x"}, "-mount needs a box file system"},
		{[]string{"-github-scope", "org", "./proj", "--", "x"}, "want repo or all"},
		{[]string{"-profile", "lax", "./proj", "--", "x"}, "want dev, strict or ci"},
	} {
		_, _, err := parseBoxArgs(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err=%v, want %q", c.args, err, c.want)
		}
	}
}

func TestBoxArgs_ManifestWithOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandbox.json")
	m := `{"version":"0.1","tier":2,"workspace":{"source":"/srv/app","exclude":["dist/*"]},
	 "agent":{"name":"reviewer","command":["opencode","run","fix"],"env":{"CI":"1"}},
	 "profile":"strict","isolation":{"image":"ghcr.io/x/box"},"limits":{"pids":100},
	 "commit_back":{"approve_timeout":"15m","disabled":true},"command_gate":false,"ui":"127.0.0.1:9191"}`
	if err := os.WriteFile(path, []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}

	o, _, err := parseBoxArgs([]string{"-manifest", path})
	if err != nil {
		t.Fatal(err)
	}
	if o.tier != 2 || o.image != "ghcr.io/x/box" || o.project != "/srv/app" || !reflect.DeepEqual(o.cmd, []string{"opencode", "run", "fix"}) ||
		o.agent != "reviewer" || !reflect.DeepEqual([]string(o.envs), []string{"CI=1"}) || !reflect.DeepEqual([]string(o.excludes), []string{"dist/*"}) ||
		o.profile != boxProfileStrict || o.pids != 100 || o.approveTimeout != 15*time.Minute || !o.noCommitBack || !o.noGate || o.ui != "127.0.0.1:9191" {
		t.Fatalf("from the manifest: %+v", o)
	}
	if o.user != boxDefaultUser || o.ghScope != "repo" || o.name != "ovara-box" {
		t.Fatalf("members the manifest leaves out keep their defaults: %+v", o)
	}

	// a flag typed next to -manifest wins, -env adds, -- replaces the command
	o, x, err := parseBoxArgs([]string{"-manifest", path, "-tier", "1", "-env", "EXTRA=2", "-events", "e.jsonl", "--", "bash"})
	if err != nil {
		t.Fatal(err)
	}
	if o.tier != 1 || !reflect.DeepEqual([]string(o.envs), []string{"CI=1", "EXTRA=2"}) || !reflect.DeepEqual(o.cmd, []string{"bash"}) || o.project != "/srv/app" || x.events != "e.jsonl" {
		t.Fatalf("overrides: %+v %+v", o, x)
	}
	// a project directory next to -manifest replaces the file's
	if o, _, err = parseBoxArgs([]string{"-manifest", path, "./other"}); err != nil || o.project != "./other" || o.cmd[0] != "opencode" {
		t.Fatalf("project override: %v %+v", err, o)
	}

	if _, _, err := parseBoxArgs([]string{"-manifest", path, "--"}); err == nil || !strings.Contains(err.Error(), "nothing after --") {
		t.Errorf("-- with nothing after it: %v", err)
	}
	if _, _, err := parseBoxArgs([]string{"-manifest", filepath.Join(dir, "missing.json")}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing manifest: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(strings.Replace(m, `"tier":2`, `"tier":2,"tire":1`, 1)), 0o600)
	if _, _, err := parseBoxArgs([]string{"-manifest", bad}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("misspelt member: %v", err)
	}
}

// Flags and manifest describe the same run: writing options down and
// reading them back changes nothing, for either tier.
func TestBoxOptions_ManifestRoundTrip(t *testing.T) {
	for name, o := range map[string]*boxOptions{
		"tier 1": {
			dir: "/etc/ovara-box", project: "/srv/app", cmd: []string{"claude", "-p", "fix"}, agent: "fixer",
			tier: 1, name: "box-a", user: "agent-a", tier1FS: tier1FSHost, visibleProcs: true, image: boxDefaultImage, pids: 4096,
			profile: boxProfileStrict, untrusted: true, ui: "127.0.0.1:9191", approveTimeout: 15 * time.Minute,
			keep: true, allowBinary: true, ghScope: "all", noGate: true,
			envs: multiFlag{"A=1", "B=2"}, excludes: multiFlag{"dist/*"},
		},
		"tier 2": {
			project: ".", cmd: []string{"opencode", "run", "x"},
			tier: 2, name: "ovara-box", user: boxDefaultUser, tier1FS: tier1FSIsolated, image: "ghcr.io/x/box", pids: 100, memory: "8g", cpus: "2",
			profile: boxProfileDev, ui: "127.0.0.1:9090", approveTimeout: 10 * time.Minute, noCommitBack: true, ghScope: "repo",
			mounts: multiFlag{"/opt/t:/opt/t"},
		},
	} {
		m := o.manifest()
		if err := m.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		again, err := sandbox.Parse(out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		back := defaultBoxOptions()
		back.applyManifest(again)
		if !reflect.DeepEqual(back, o) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v\n%s", name, back, o, out)
		}
	}
}

// -print-manifest needs no root and no Linux: it writes the run down and stops.
func TestBoxPrintManifest(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	err = cmdBox([]string{"-print-manifest", "-tier", "2", "-image", "img", "-no-commit-back", "./proj", "--", "opencode", "run", "x"})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	m, err := sandbox.Parse(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if m.Tier != 2 || m.Isolation.Image != "img" || !m.CommitBack.Disabled || m.Workspace.Source != "./proj" || !reflect.DeepEqual(m.Agent.Command, []string{"opencode", "run", "x"}) {
		t.Fatalf("%s", out)
	}
}

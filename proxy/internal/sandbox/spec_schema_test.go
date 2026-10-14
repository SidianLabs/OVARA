package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func specSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, "spec", "schemas", name)
		if b, err := os.ReadFile(p); err == nil {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			return m
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("spec/schemas/%s not found above %s", name, dir)
		}
		dir = parent
	}
}

// members of a schema node, and of a Go struct's JSON encoding
func schemaMembers(node map[string]any) []string {
	p, _ := node["properties"].(map[string]any)
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func codeMembers(v any) []string {
	var out []string
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// The published schemas name exactly the members this package reads and
// writes, at every level.
func TestSpecSchemasMatchTheCode(t *testing.T) {
	check := func(what string, node map[string]any, v any) {
		t.Helper()
		if got, want := schemaMembers(node), codeMembers(v); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema %v, code %v", what, got, want)
		}
	}
	m := specSchema(t, "manifest.schema.json")
	defs, _ := m["$defs"].(map[string]any)
	check("manifest", m, Manifest{})
	check("workspace", defs["workspace"].(map[string]any), Workspace{})
	check("agent", defs["agent"].(map[string]any), Agent{})
	check("isolation", defs["isolation"].(map[string]any), Isolation{})
	check("limits", defs["limits"].(map[string]any), Limits{})
	check("credentials", defs["credentials"].(map[string]any), Credentials{})
	check("commit_back", defs["commit_back"].(map[string]any), CommitBack{})
	if v, _ := m["properties"].(map[string]any)["version"].(map[string]any); v["const"] != Version {
		t.Errorf("manifest version: schema %v, code %q", v["const"], Version)
	}

	e := specSchema(t, "event.schema.json")
	defs, _ = e["$defs"].(map[string]any)
	check("event", e, Event{})
	check("summary", defs["summary"].(map[string]any), Summary{})
	check("counts", defs["counts"].(map[string]any), Counts{})
	if v, _ := e["properties"].(map[string]any)["v"].(map[string]any); v["const"] != float64(EventVersion) {
		t.Errorf("event version: schema %v, code %d", v["const"], EventVersion)
	}
	// every event name the code emits is one the schema allows, and the other way round
	names, _ := e["properties"].(map[string]any)["event"].(map[string]any)["enum"].([]any)
	fromSchema := make([]string, 0, len(names))
	for _, n := range names {
		fromSchema = append(fromSchema, n.(string))
	}
	fromCode := []string{EventRunCreated, EventWorkspaceCopied, EventProxyStarted, EventAgentStarted,
		EventCommandAllowed, EventCommandRefused, EventCommandPaused, EventCommandApproved, EventCommandNotApproved,
		EventAgentExited, EventCommitBackDisabled, EventCommitBackNothing, EventCommitBackKept, EventCommitBackRefused,
		EventCommitBackWaiting, EventCommitBackNotApproved, EventCommitBackLanded, EventRunFinished}
	sort.Strings(fromSchema)
	sort.Strings(fromCode)
	if !reflect.DeepEqual(fromSchema, fromCode) {
		t.Errorf("event names: schema %v, code %v", fromSchema, fromCode)
	}
}

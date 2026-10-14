package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func specSchema(t *testing.T) map[string]any {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, "spec", "schemas", "attestation.schema.json")
		if b, err := os.ReadFile(p); err == nil {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			return m
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("spec/schemas/attestation.schema.json not found above %s", dir)
		}
		dir = parent
	}
}

func jsonNames(v any) []string {
	rt := reflect.TypeOf(v)
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The published schema names exactly the members the code writes, at
// every level, and the constants are the ones the code checks.
func TestSpecAttestationSchemaMatchesTheCode(t *testing.T) {
	schema := specSchema(t)
	props := schema["properties"].(map[string]any)
	defs := schema["$defs"].(map[string]any)
	at := func(m map[string]any, path ...string) map[string]any {
		for _, p := range path {
			m = m[p].(map[string]any)
		}
		return m
	}
	cases := []struct {
		what string
		code any
		spec map[string]any
	}{
		{"envelope", Envelope{}, props},
		{"signature", Signature{}, at(props, "signatures", "items", "properties")},
		{"statement", Statement{}, at(defs, "statement", "properties")},
		{"subject", Subject{}, at(defs, "subject", "properties")},
		{"predicate", Predicate{}, at(defs, "predicate", "properties")},
		{"digest", Digest{}, at(defs, "digest", "properties")},
		{"policy", Policy{}, at(defs, "policy", "properties")},
		{"receipts", Receipts{}, at(defs, "receipts", "properties")},
		{"approval", Approval{}, at(defs, "approval", "properties")},
		{"host", Host{}, at(defs, "host", "properties")},
	}
	for _, c := range cases {
		if got, want := keys(c.spec), jsonNames(c.code); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema %v, code %v", c.what, got, want)
		}
	}
	if props["payloadType"].(map[string]any)["const"] != PayloadType {
		t.Errorf("payloadType const")
	}
	if at(defs, "statement", "properties", "_type")["const"] != StatementType || at(defs, "statement", "properties", "predicateType")["const"] != PredicateType {
		t.Errorf("statement constants")
	}
	runtimes := at(defs, "predicate", "properties", "runtime")["enum"].([]any)
	if len(runtimes) != 2 || runtimes[0] != RuntimeBox || runtimes[1] != RuntimeRun {
		t.Errorf("runtime enum %v", runtimes)
	}
}

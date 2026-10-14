package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// specSchema reads spec/schemas/<name> from the repository root.
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

// jsonFields are the JSON member names a struct encodes (its json tags).
func jsonFields(v any) map[string]bool {
	out := map[string]bool{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = true
	}
	return out
}

func schemaProps(t *testing.T, schema map[string]any, path ...string) map[string]bool {
	t.Helper()
	cur := any(schema)
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: not an object at %q", path, p)
		}
		cur = m[p]
	}
	props, ok := cur.(map[string]any)
	if !ok {
		t.Fatalf("schema path %v: no properties", path)
	}
	out := map[string]bool{}
	for k := range props {
		out[k] = true
	}
	return out
}

// The published policy schema (spec/schemas/policy.schema.json) names
// exactly the members the code reads: a field added to Rule or filePolicy
// without the schema, or the other way round, fails here.
func TestSpecPolicySchemaMatchesTheCode(t *testing.T) {
	schema := specSchema(t, "policy.schema.json")
	if got, want := schemaProps(t, schema, "$defs", "rule", "properties"), jsonFields(Rule{}); !reflect.DeepEqual(got, want) {
		t.Errorf("rule members: schema %v, code %v", keys(got), keys(want))
	}
	if got, want := schemaProps(t, schema, "properties"), jsonFields(filePolicy{}); !reflect.DeepEqual(got, want) {
		t.Errorf("document members: schema %v, code %v", keys(got), keys(want))
	}
	// The enumerations are the constants the loader accepts.
	prec := schema["properties"].(map[string]any)["precedence"].(map[string]any)["enum"].([]any)
	if len(prec) != 2 || prec[0] != PrecedenceOrder || prec[1] != PrecedenceMostSpecific {
		t.Errorf("precedence enum %v", prec)
	}
	def := schema["properties"].(map[string]any)["default"].(map[string]any)["enum"].([]any)
	if len(def) != 2 || def[0] != DefaultEscalate || def[1] != DefaultDeny {
		t.Errorf("default enum %v", def)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

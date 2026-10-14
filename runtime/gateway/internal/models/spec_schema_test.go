package models

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

func jsonFields(v any) []string {
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

func schemaProps(t *testing.T, schema map[string]any) []string {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The published decision request and response schemas name exactly the
// members the code encodes (spec/schemas/decision-*.schema.json).
func TestSpecDecisionSchemasMatchTheCode(t *testing.T) {
	if got, want := schemaProps(t, specSchema(t, "decision-request.schema.json")), jsonFields(ActionRequest{}); !reflect.DeepEqual(got, want) {
		t.Errorf("request members: schema %v, code %v", got, want)
	}
	if got, want := schemaProps(t, specSchema(t, "decision-response.schema.json")), jsonFields(DecisionResponse{}); !reflect.DeepEqual(got, want) {
		t.Errorf("response members: schema %v, code %v", got, want)
	}
	dec := specSchema(t, "decision-response.schema.json")["properties"].(map[string]any)["decision"].(map[string]any)["enum"].([]any)
	if len(dec) != 3 || dec[0] != string(DecisionAllow) || dec[1] != string(DecisionDeny) || dec[2] != string(DecisionEscalate) {
		t.Errorf("decision enum %v", dec)
	}
}

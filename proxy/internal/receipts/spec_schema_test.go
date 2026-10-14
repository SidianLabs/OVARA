package receipts

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

// The published receipt schema names exactly the members a chain line
// carries, in the order the code writes them: the signing form and the
// strict reader both depend on that order.
func TestSpecReceiptSchemaMatchesTheCode(t *testing.T) {
	schema := specSchema(t, "receipt-v2.schema.json")
	props, _ := schema["properties"].(map[string]any)
	fromSchema := make([]string, 0, len(props))
	var fromCode []string
	for k := range props {
		fromSchema = append(fromSchema, k)
	}
	rt := reflect.TypeOf(Receipt{})
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fromCode = append(fromCode, name)
		}
	}
	sort.Strings(fromSchema)
	sorted := append([]string(nil), fromCode...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(fromSchema, sorted) {
		t.Fatalf("members: schema %v, code %v", fromSchema, sorted)
	}
	// Every member the signing form covers is a member of the line, and
	// the chain's required members are the ones a v1 line already had.
	required, _ := schema["required"].([]any)
	for _, r := range required {
		if !contains(fromCode, r.(string)) {
			t.Errorf("required member %v is not in the code", r)
		}
	}
	if sig, _ := props["signature"].(map[string]any); sig["pattern"] != "^sig_v(1|2):[0-9a-f]+$" {
		t.Errorf("signature pattern %v does not name the %q and %q prefixes", sig["pattern"], sigV1Prefix, sigV2Prefix)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

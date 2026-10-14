package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, dir string, rules []map[string]any) {
	t.Helper()
	doc := map[string]any{"version": "v2-init", "precedence": "most-specific", "rules": rules}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func ruleSet(t *testing.T, dir string) (all []any, profile int, resources map[string]string) {
	t.Helper()
	_, rules, err := readPolicyDoc(dir)
	if err != nil {
		t.Fatal(err)
	}
	resources = map[string]string{}
	for _, r := range rules {
		rm := r.(map[string]any)
		if _, ok := profileOf(r); ok {
			profile++
		}
		action, _ := rm["action_type"].(string)
		resource, _ := rm["resource"].(string) // the defaults leave an empty resource out
		for _, effect := range []string{"allow", "deny", "escalate"} {
			if rm[effect] == true {
				resources[action+" "+resource] = effect
			}
		}
	}
	return rules, profile, resources
}

// Switching profiles replaces the previous profile's rules and nothing
// else: the defaults and the person's own rules stay as they were.
func TestProfiles_SwitchReplacesOnlyTheProfileRules(t *testing.T) {
	dir := t.TempDir()
	mine := map[string]any{"action_type": "http.request", "environment": "*", "resource": "GET https://mine.example/*", "allow": true, "description": "mine"}
	writePolicy(t, dir, append(defaultPolicyRules(), mine))
	_, n, _ := ruleSet(t, dir)
	if n != 0 {
		t.Fatalf("the defaults carry %d profile rules", n)
	}
	base := len(defaultPolicyRules()) + 1

	was, err := applyProfile(dir, profileBalanced)
	if err != nil || was != profileStrict {
		t.Fatalf("to balanced: %v, was %q", err, was)
	}
	all, n, res := ruleSet(t, dir)
	if len(all) != base+2 || n != 2 || res["http.request GET *"] != "allow" || res["http.request HEAD *"] != "allow" || res["http.request GET https://mine.example/*"] != "allow" {
		t.Fatalf("balanced: %d rules (%d profile), %v", len(all), n, res)
	}
	for _, r := range all {
		if rm := r.(map[string]any); rm["resource"] == "GET *" {
			d := rm["description"].(string)
			if !strings.HasPrefix(d, "[profile balanced] "+openReadMarker) {
				t.Fatalf("the open read rule is marked for the proxy: %q", d)
			}
		}
	}

	was, err = applyProfile(dir, profileObserve)
	if err != nil || was != profileBalanced {
		t.Fatalf("to observe: %v, was %q", err, was)
	}
	all, n, res = ruleSet(t, dir)
	if len(all) != base+8 || n != 8 {
		t.Fatalf("observe: %d rules (%d profile)", len(all), n)
	}
	for k, want := range map[string]string{
		"http.request GET *": "allow", "http.request HEAD *": "allow",
		"http.request POST *": "deny", "http.request PUT *": "deny", "http.request PATCH *": "deny", "http.request DELETE *": "deny",
		"model.server_feature model:*": "deny", "mcp.tool_call mcp:*": "deny",
		// the defaults' own questions are still there
		"model.server_feature *": "escalate", "mcp.tool_call *": "escalate", "http.request GET https://mine.example/*": "allow",
	} {
		if res[k] != want {
			t.Errorf("observe: %s = %q, want %q", k, res[k], want)
		}
	}
	for _, r := range all {
		if name, ok := profileOf(r); ok && name != profileObserve {
			t.Fatalf("a %s rule survived the switch", name)
		}
	}

	was, err = applyProfile(dir, profileStrict)
	if err != nil || was != profileObserve {
		t.Fatalf("to strict: %v, was %q", err, was)
	}
	if all, n, res := ruleSet(t, dir); len(all) != base || n != 0 || res["http.request GET https://mine.example/*"] != "allow" {
		t.Fatalf("strict again: %d rules (%d profile)", len(all), n)
	}
	if _, err := applyProfile(dir, "lax"); err == nil || !strings.Contains(err.Error(), "want strict, balanced, observe") {
		t.Fatalf("unknown profile: %v", err)
	}
}

// An older policy file decides by effect order, where an allow beats an
// escalate: a catch-all read allow would stop the credentialed reads of
// secrets from pausing. The open-read profiles refuse such a file.
func TestProfiles_NeedMostSpecificPrecedence(t *testing.T) {
	dir := t.TempDir()
	doc := map[string]any{"version": "v2-init", "rules": defaultPolicyRules()}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{profileBalanced, profileObserve} {
		if _, err := applyProfile(dir, p); err == nil || !strings.Contains(err.Error(), "most-specific") {
			t.Errorf("%s on a legacy-order file: %v", p, err)
		}
	}
	if _, err := applyProfile(dir, profileStrict); err != nil {
		t.Fatalf("strict is fine on any file: %v", err)
	}
	if _, n, _ := ruleSet(t, dir); n != 0 {
		t.Fatalf("%d profile rules on a file that was refused", n)
	}
}

func TestProfiles_ShowNamesTheCurrentOne(t *testing.T) {
	var buf bytes.Buffer
	printProfiles(&buf, profileObserve)
	out := buf.String()
	if !strings.HasPrefix(out, "current profile: observe\n") || !strings.Contains(out, "strict:") || !strings.Contains(out, "balanced:") || !strings.Contains(out, "ovara policy profile <strict|balanced|observe>") {
		t.Fatalf("%s", out)
	}
}

// `ovara init -profile` writes the profile into the new deployment.
func TestInit_Profile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := cmdInit([]string{dir, "-profile", "balanced"}); err != nil {
		t.Fatal(err)
	}
	_, rules, err := readPolicyDoc(dir)
	if err != nil || currentProfile(rules) != profileBalanced {
		t.Fatalf("%v, profile %q", err, currentProfile(rules))
	}
	if err := cmdInit([]string{filepath.Join(t.TempDir(), "e"), "-profile", "lax"}); err == nil || !strings.Contains(err.Error(), "want strict") {
		t.Fatalf("unknown profile at init: %v", err)
	}
}

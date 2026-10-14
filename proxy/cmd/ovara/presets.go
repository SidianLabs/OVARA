package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/proxy"
)

// A preset is what a known agent needs beyond the default policy to start
// and work through Ovara: the hosts it reads on its own at start-up, and
// the model API it calls. Writes still ask. The hosts are the ones the
// agents matrix in CI (tests/agents) records each agent contacting while it
// runs against a mock model; nothing here is a guess about an agent.
type preset struct {
	Name string
	// Reads are hosts the agent fetches on its own (GET/HEAD allowed).
	Reads []string
	// Model are inference endpoints the agent calls: POST allowed there, and
	// the host is added to model_hosts so the model gate reads every body.
	Model []modelEndpoint
}

type modelEndpoint struct{ Host, Path string }

var presets = []preset{
	{Name: "opencode",
		Reads: []string{"models.opencode.ai"},                 // the model catalogue, fetched at start
		Model: []modelEndpoint{{"opencode.ai", "/zen/v1/*"}}}, // its free models
	{Name: "claude"}, // Claude Code: api.anthropic.com is allowed and bound by default
	{Name: "codex", Reads: []string{"chatgpt.com", "ab.chatgpt.com"}}, // sign-in and feature flags
}

// presetFor returns the preset for an agent command, by the program's base
// name ("opencode", "claude", "codex"; a path or a .exe suffix is fine).
func presetFor(argv0 string) (preset, bool) {
	name := argv0
	if i := strings.LastIndexAny(name, `/\`); i >= 0 { // a path from either platform
		name = name[i+1:]
	}
	name = strings.ToLower(strings.TrimSuffix(name, ".exe"))
	for _, p := range presets {
		if p.Name == name {
			return p, true
		}
	}
	return preset{}, false
}

// presetNamed returns the preset called name.
func presetNamed(name string) (preset, bool) {
	for _, p := range presets {
		if p.Name == name {
			return p, true
		}
	}
	return preset{}, false
}

// presetMarker starts the description of every rule a preset adds, so the
// rules are recognised (never added twice) and a person can see where they
// came from.
func presetMarker(p preset) string { return "[preset " + p.Name + "]" }

// applyPreset adds the preset's rules to the deployment's policy.json and
// its model hosts to proxy.json, once; it returns what it added. Rules a
// person already has are left alone.
func applyPreset(dir string, p preset) (added []string, err error) {
	policyPath := filepath.Join(dir, "policy.json")
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("%s: %w", policyPath, err)
	}
	var rules []map[string]any
	if err := json.Unmarshal(policy["rules"], &rules); err != nil {
		return nil, fmt.Errorf("%s: rules: %w", policyPath, err)
	}
	have := map[string]bool{}
	for _, r := range rules {
		if res, _ := r["resource"].(string); res != "" {
			have[res] = true
		}
	}
	rule := func(resource, why string) {
		if have[resource] {
			return
		}
		rules = append(rules, map[string]any{
			"action_type": "http.request", "environment": "*", "resource": resource, "allow": true,
			"description": presetMarker(p) + " " + why,
		})
		added = append(added, resource)
	}
	for _, h := range p.Reads {
		for _, m := range []string{"GET", "HEAD"} {
			rule(m+" https://"+h+"/*", h+": the agent reads this on its own")
		}
	}
	for _, m := range p.Model {
		rule("POST https://"+m.Host+m.Path, m.Host+": the agent's model API (bodies are checked by the model gate)")
	}
	if len(added) > 0 {
		policy["rules"], _ = json.Marshal(rules)
		out, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := config.WriteFileAtomic(policyPath, append(out, '\n'), 0o600); err != nil {
			return nil, err
		}
	}
	if len(p.Model) > 0 {
		if err := addModelHosts(filepath.Join(dir, "proxy.json"), p.Model); err != nil {
			return added, err
		}
	}
	return added, nil
}

// addModelHosts adds hosts to proxy.json's model_hosts, keeping the default
// hosts when the file names none (a list replaces the default, so the
// default is written out with it).
func addModelHosts(proxyJSON string, eps []modelEndpoint) error {
	raw, err := os.ReadFile(proxyJSON)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s: %w", proxyJSON, err)
	}
	var hosts []string
	if v, ok := doc["model_hosts"]; ok {
		_ = json.Unmarshal(v, &hosts)
	}
	if hosts == nil {
		hosts = proxy.DefaultModelHosts()
	}
	changed := false
	for _, ep := range eps {
		found := false
		for _, h := range hosts {
			if h == ep.Host {
				found = true
			}
		}
		if !found {
			hosts = append(hosts, ep.Host)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	doc["model_hosts"], _ = json.Marshal(hosts)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(proxyJSON, append(out, '\n'), 0o600)
}

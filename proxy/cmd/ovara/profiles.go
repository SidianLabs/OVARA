package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Policy profiles: what an agent may do without asking, as a named rule
// set on top of the policy `ovara init` writes.
//
//	strict    reads only from the trusted hosts; everything else asks
//	balanced  reads from any public host, bounded (each read's size, per-host
//	          metering, a per-agent cap on unlisted hosts) and receipted;
//	          writes, credentialed reads of secrets and tool calls ask as before
//	observe   reads from any public host; writes and outbound actions are
//	          refused at once, never held; `ovara policy suggest` turns the
//	          run's receipts into the rules a strict policy would need
//
// A profile's rules carry "[profile NAME]" in their description, so
// switching profiles replaces exactly those rules and nothing else: the
// defaults, the person's own rules, presets and per-run trust stay. Under
// most-specific precedence the strict guards keep deciding next to the
// profile's catch-alls (runtime/gateway/internal/evaluator,
// TestMostSpecific_OpenReadProfilesKeepTheGuards).

const (
	profileStrict   = "strict"
	profileBalanced = "balanced"
	profileObserve  = "observe"

	// openReadMarker is on every rule that lets reads through to any
	// host. The proxy counts the distinct hosts an agent reads under such
	// a rule and asks past open_reads.max_hosts (proxy.json).
	openReadMarker = "[open read]"
)

var profileNames = []string{profileStrict, profileBalanced, profileObserve}

func profileMarker(name string) string { return "[profile " + name + "]" }

func validProfile(name string) error {
	for _, p := range profileNames {
		if p == name {
			return nil
		}
	}
	return fmt.Errorf("profile %q: want %s", name, strings.Join(profileNames, ", "))
}

// profileRules is what name adds to the strict policy; nothing for strict.
func profileRules(name string) []map[string]any {
	rule := func(action, resource, effect, desc string) map[string]any {
		return map[string]any{"action_type": action, "environment": "*", "resource": resource, "description": profileMarker(name) + " " + desc, effect: true}
	}
	openReads := func() []map[string]any {
		why := openReadMarker + " Reading from any public host is allowed: each read is bounded (max_read_request_bytes), metered per host (egress_budget), counted per agent (open_reads.max_hosts distinct unlisted hosts per run, then a question per further host) and receipted; a write soon after an untrusted read still pauses"
		return []map[string]any{
			rule("http.request", "GET *", "allow", why),
			rule("http.request", "HEAD *", "allow", why),
		}
	}
	switch name {
	case profileBalanced:
		return openReads()
	case profileObserve:
		rules := openReads()
		for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			rules = append(rules, rule("http.request", m+" *", "deny", "Refused, not held: the observe profile writes nothing to the world (ovara policy suggest lists what was refused)"))
		}
		// more specific than the defaults' "*", so these win without a tie
		rules = append(rules,
			rule("model.server_feature", "model:*", "deny", "Refused, not held: a model request that makes the provider reach out for the agent is an outbound action (observe profile)"),
			rule("mcp.tool_call", "mcp:*", "deny", "Refused, not held: MCP tool calls act on the world (observe profile; ovara policy suggest lists the tools called)"),
		)
		return rules
	}
	return nil
}

// currentProfile reads the profile marked in rules: strict when none is.
func currentProfile(rules []any) string {
	for _, r := range rules {
		if name, ok := profileOf(r); ok {
			return name
		}
	}
	return profileStrict
}

// profileOf returns the profile a rule belongs to, by its marker.
func profileOf(r any) (string, bool) {
	rm, ok := r.(map[string]any)
	if !ok {
		return "", false
	}
	desc, _ := rm["description"].(string)
	if !strings.HasPrefix(desc, "[profile ") {
		return "", false
	}
	name, _, ok := strings.Cut(strings.TrimPrefix(desc, "[profile "), "]")
	return name, ok
}

// applyProfile makes name the deployment's profile: the previous profile's
// rules go, name's come (at the end: precedence is by specificity, not
// position). It returns the profile replaced. The gateway reloads
// policy.json on its own.
func applyProfile(dir, name string) (was string, err error) {
	if err := validProfile(name); err != nil {
		return "", err
	}
	doc, rules, err := readPolicyDoc(dir)
	if err != nil {
		return "", err
	}
	// A catch-all read allow is safe only where the most specific rule
	// decides: under the older order an allow beats an escalate, and the
	// credentialed reads that must pause would stop pausing.
	if p, _ := doc["precedence"].(string); name != profileStrict && p != "most-specific" {
		return "", fmt.Errorf("the %s profile needs \"precedence\": \"most-specific\" in policy.json (what ovara init writes): under the older order its catch-all read allow would beat the rules that pause credentialed reads of secrets; add the field, check your rules with `ovara policy test`, then switch", name)
	}
	was = currentProfile(rules)
	kept := make([]any, 0, len(rules))
	for _, r := range rules {
		if _, ok := profileOf(r); !ok {
			kept = append(kept, r)
		}
	}
	for _, r := range profileRules(name) {
		kept = append(kept, r)
	}
	doc["rules"] = kept
	return was, writePolicyDoc(dir, doc)
}

// profileSummary is the one-paragraph account of a profile that `ovara
// init` and `ovara policy profile` print.
func profileSummary(name string) string {
	switch name {
	case profileBalanced:
		return "balanced: the agent reads from any public host without asking; each read is bounded, traffic is metered per host, the distinct unlisted hosts it reads are capped per run (open_reads in proxy.json, 50 by default), every read leaves a receipt, and a write soon after an untrusted read pauses. Writes, credentialed reads of secrets and tool calls ask as before; known data-dump sites stay blocked."
	case profileObserve:
		return "observe: the agent reads from any public host; writes, provider-side fetches and MCP tool calls are refused at once (never held), so a run never stalls and changes nothing in the world. Afterwards `ovara policy suggest` turns its receipts into the rules a strict policy would need."
	}
	return "strict: reads only from the trusted hosts (package registries, code hosts, documentation); everything else pauses for your approval; known data-dump sites are blocked."
}

// cmdPolicyProfile: `ovara policy profile [NAME] [-dir DIR]` shows or
// switches the deployment's profile.
func cmdPolicyProfile(args []string) error {
	fs := flag.NewFlagSet("policy profile", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote policy.json)")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if name == "" {
		_, rules, err := readPolicyDoc(*dir)
		if err != nil {
			return err
		}
		printProfiles(os.Stdout, currentProfile(rules))
		return nil
	}
	was, err := applyProfile(*dir, name)
	if err != nil {
		return err
	}
	if was == name {
		fmt.Printf("profile %s already in place in %s (its rules rewritten)\n", name, *dir)
	} else {
		fmt.Printf("profile %s -> %s in %s; the gateway reloads policy.json on its own\n", was, name, *dir)
	}
	fmt.Println(profileSummary(name))
	return nil
}

func printProfiles(w io.Writer, current string) {
	fmt.Fprintf(w, "current profile: %s\n\n", current)
	for _, p := range profileNames {
		fmt.Fprintf(w, "  %s\n\n", profileSummary(p))
	}
	fmt.Fprintln(w, "switch with:  ovara policy profile <strict|balanced|observe> -dir DIR")
}

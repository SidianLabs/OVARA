package main

import (
	"fmt"
	"strings"
	"time"
)

// "Approve and remember": the rule an approval leaves behind, with a
// scope. Each scope is one exact thing: a named host's reads, one command
// line, one tool. Never a wildcard (a "*" in the resource would make the
// rule a pattern, so such a request offers nothing), never a write to the
// world. Run-scoped rules carry runTrustMarker and go when `ovara run`
// stops; a project-scoped rule stays until a person removes it. Every
// rule says who remembered it, when, and from which approval.

type rememberScope struct {
	Key     string `json:"key"`     // what the page and the CLI pass
	Label   string `json:"label"`   // the button, and the watch menu
	Confirm string `json:"confirm"` // what the person is told before it happens
}

// action types a remembered rule can be for
const (
	actionHTTPRequest = "http.request"
	actionShell       = "shell"
	actionMCPToolCall = "mcp.tool_call"
)

const (
	scopeReadsRun     = "reads-run"
	scopeReadsProject = "reads-project"
	scopeCommandRun   = "command-run"
	scopeToolRun      = "tool-run"

	// projectMarker starts the description of a rule remembered for the
	// project: it stays after the run, unlike runTrustMarker.
	projectMarker = "[remembered]"
	readCaveat    = "A read can still carry data out (in its path and headers). Only do this for a host you trust."
)

// rememberOptions is what an approval can be remembered as, in the order
// a person should see them.
func rememberOptions(a pendingApproval) []rememberScope {
	switch a.ActionType {
	case actionHTTPRequest:
		host, ok := trustableHost(a.Resource)
		if !ok {
			return nil
		}
		return []rememberScope{
			{scopeReadsRun, "Approve, and stop asking about reads from " + host,
				"Reads from " + host + " will no longer be asked about until ovara run stops.\n\n" + readCaveat},
			{scopeReadsProject, "Approve, and allow reads from " + host + " for this project",
				"Reads from " + host + " will no longer be asked about, in this run and the next ones, until the rule is removed from policy.json.\n\n" + readCaveat},
		}
	case actionShell:
		line, ok := strings.CutPrefix(a.Resource, "shell:")
		if !ok || line == "" || strings.Contains(line, "*") {
			return nil
		}
		return []rememberScope{{scopeCommandRun, "Approve, and allow exactly this command until ovara run stops",
			"The command `" + line + "` will run without asking until ovara run stops. Any other command line still asks."}}
	case actionMCPToolCall:
		if !strings.HasPrefix(a.Resource, "mcp:") || strings.Contains(a.Resource, "*") {
			return nil
		}
		return []rememberScope{{scopeToolRun, "Approve, and allow this tool until ovara run stops",
			"Calls of " + a.Resource + " will no longer be asked about until ovara run stops. Other tools still ask."}}
	}
	return nil
}

// offersScope reports whether key is one of the scopes a offers.
func offersScope(a pendingApproval, key string) bool {
	for _, o := range rememberOptions(a) {
		if o.Key == key {
			return true
		}
	}
	return false
}

// rememberKeys names the scopes a request offers, for an error message.
func rememberKeys(a pendingApproval) string {
	options := rememberOptions(a)
	keys := make([]string, 0, len(options))
	for _, o := range options {
		keys = append(keys, o.Key)
	}
	if len(keys) == 0 {
		return "nothing: a write, a wildcard, or a read from an unnamed host is never remembered"
	}
	return strings.Join(keys, ", ")
}

// remember adds the rule(s) for scope to policy.json, at the front, unless
// they are already there. who may be empty.
func remember(dir string, a pendingApproval, scope, who string) (added bool, err error) {
	if !offersScope(a, scope) {
		return false, fmt.Errorf("this request cannot be remembered as %q; it offers %s", scope, rememberKeys(a))
	}
	by := ""
	if who != "" {
		by = " by " + who
	}
	from := ""
	if a.ApprovalID != "" {
		from = " (approval " + a.ApprovalID + ")"
	}
	day := time.Now().Format("2006-01-02")
	var fresh []map[string]any
	rule := func(action, resource, desc string) {
		fresh = append(fresh, map[string]any{"action_type": action, "environment": "*", "resource": resource, "allow": true, "description": desc})
	}
	switch scope {
	case scopeReadsRun, scopeReadsProject:
		host, _ := trustableHost(a.Resource)
		for _, m := range []string{"GET", "HEAD"} {
			if scope == scopeReadsRun {
				rule(actionHTTPRequest, m+" https://"+host+"/*", fmt.Sprintf("%s Reads from %s trusted from the approval prompt (page or ovara watch)%s on %s%s; removed when ovara run stops (delete %q from this description to keep it)",
					runTrustMarker, host, by, day, from, runTrustMarker))
			} else {
				rule(actionHTTPRequest, m+" https://"+host+"/*", fmt.Sprintf("%s Reads from %s allowed for this project from the approval prompt%s on %s%s; remove this rule to undo",
					projectMarker, host, by, day, from))
			}
		}
	case scopeCommandRun:
		rule(actionShell, a.Resource, fmt.Sprintf("%s This command allowed from the approval prompt%s on %s%s; removed when ovara run stops", runTrustMarker, by, day, from))
	case scopeToolRun:
		rule(actionMCPToolCall, a.Resource, fmt.Sprintf("%s This MCP tool allowed from the approval prompt%s on %s%s; removed when ovara run stops", runTrustMarker, by, day, from))
	}
	doc, rules, err := readPolicyDoc(dir)
	if err != nil {
		return false, err
	}
	var add []any
	for _, f := range fresh {
		exists := false
		for _, r := range rules {
			if rm, ok := r.(map[string]any); ok && rm["resource"] == f["resource"] && rm["action_type"] == f["action_type"] && rm["allow"] == true {
				exists = true
				break
			}
		}
		if !exists {
			add = append(add, f)
		}
	}
	if len(add) == 0 {
		return false, nil
	}
	doc["rules"] = append(add, rules...)
	return true, writePolicyDoc(dir, doc)
}

// rememberedNote is the one line that tells a person what remembering did.
func rememberedNote(a pendingApproval, scope string) string {
	host, _ := trustableHost(a.Resource)
	switch scope {
	case scopeReadsRun:
		return "trusted " + host + " for reads: GET/HEAD there will no longer ask until ovara run stops (edit policy.json to undo sooner). " + readCaveat
	case scopeReadsProject:
		return "allowed reads from " + host + " for this project: GET/HEAD there will no longer ask, in this run and the next ones, until the rule is removed from policy.json. " + readCaveat
	case scopeCommandRun:
		return "allowed exactly this command until ovara run stops; any other command line still asks."
	case scopeToolRun:
		return "allowed this tool until ovara run stops; other tools still ask."
	}
	return ""
}

// describeRemembered words what dropRunTrust returned: a bare host is a
// host whose reads were trusted; the rest already say what they are.
func describeRemembered(what []string) string {
	out := make([]string, 0, len(what))
	for _, w := range what {
		if !strings.Contains(w, " ") {
			w = "reads from " + w
		}
		out = append(out, w)
	}
	return strings.Join(out, ", ")
}

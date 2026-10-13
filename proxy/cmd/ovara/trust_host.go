package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// "Approve and remember": after a human lets one read through, they can trust
// that host for reads so the same prompt does not come back for every page.
//
// It is deliberately narrow. It adds a GET/HEAD allow rule for ONE exact
// host. It never trusts a wildcard, an IP literal or a non-https URL, and it
// is offered only for reads: a POST, push or delete is judged on its own
// every time.

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// trustableHost returns the host of a GET/HEAD https resource, if it is safe
// to offer "trust this host for reads" for it.
func trustableHost(resource string) (string, bool) {
	method, rest, ok := strings.Cut(resource, " ")
	if !ok || (method != "GET" && method != "HEAD") {
		return "", false
	}
	target, _, _ := strings.Cut(rest, " ")
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !hostPattern.MatchString(h) || net_isIP(h) {
		return "", false
	}
	return h, true
}

func net_isIP(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

// runTrustMarker starts the description of every rule trustReadHost adds.
// `ovara run` removes such rules when it stops and when it starts (after a
// crash), so trusting a host from an approval prompt lasts one run. A
// person who wants to keep one deletes the marker from its description.
const runTrustMarker = "[this run only]"

// trustReadHost adds "GET/HEAD https://<host>/*" allow rules to policy.json,
// at the front, unless they are already there. The gateway reloads the file
// on its own. The write is atomic (temp file + rename). The rules say they
// came from an approval prompt, when, and that they last this run only.
//
// Once a host is trusted, reads from it no longer ask, and a read can still
// carry data out in its path and headers; so the prompt that offers this
// says so, and the trust ends with the run.
func trustReadHost(dir, host string) (added bool, err error) {
	doc, rules, err := readPolicyDoc(dir)
	if err != nil {
		return false, err
	}
	var fresh []any
	for _, m := range []string{"GET", "HEAD"} {
		resource := m + " https://" + host + "/*"
		exists := false
		for _, r := range rules {
			if rm, ok := r.(map[string]any); ok && rm["resource"] == resource && rm["allow"] == true {
				exists = true
				break
			}
		}
		if !exists {
			fresh = append(fresh, map[string]any{
				"action_type": "http.request", "environment": "*", "resource": resource, "allow": true,
				"description": fmt.Sprintf("%s Reads from %s trusted from the approval prompt (page or ovara watch) on %s; removed when ovara run stops (delete %q from this description to keep it)",
					runTrustMarker, host, time.Now().Format("2006-01-02"), runTrustMarker),
			})
		}
	}
	if len(fresh) == 0 {
		return false, nil
	}
	doc["rules"] = append(fresh, rules...)
	return true, writePolicyDoc(dir, doc)
}

// dropRunTrust removes the rules trustReadHost added (they still carry the
// marker) and returns the hosts they were for. Nothing else is touched.
func dropRunTrust(dir string) (hosts []string, err error) {
	doc, rules, err := readPolicyDoc(dir)
	if err != nil {
		return nil, err
	}
	var keep []any
	seen := map[string]bool{}
	for _, r := range rules {
		if host, ok := runTrustRule(r); ok {
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
			continue
		}
		keep = append(keep, r)
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	if keep == nil {
		keep = []any{}
	}
	doc["rules"] = keep
	return hosts, writePolicyDoc(dir, doc)
}

// runTrustRule reports whether r is exactly a rule trustReadHost adds, with
// the marker still in place, and for which host.
func runTrustRule(r any) (string, bool) {
	rm, ok := r.(map[string]any)
	if !ok || rm["allow"] != true || rm["action_type"] != "http.request" {
		return "", false
	}
	if desc, _ := rm["description"].(string); !strings.HasPrefix(desc, runTrustMarker) {
		return "", false
	}
	res, _ := rm["resource"].(string)
	for _, m := range []string{"GET", "HEAD"} {
		if host, ok := strings.CutPrefix(res, m+" https://"); ok {
			if host, ok = strings.CutSuffix(host, "/*"); ok && hostPattern.MatchString(host) {
				return host, true
			}
		}
	}
	return "", false
}

func readPolicyDoc(dir string) (map[string]any, []any, error) {
	path := filepath.Join(dir, "policy.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	rules, _ := doc["rules"].([]any)
	return doc, rules, nil
}

// writePolicyDoc replaces policy.json atomically, keeping its mode.
func writePolicyDoc(dir string, doc map[string]any) error {
	path := filepath.Join(dir, "policy.json")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmp.Name(), fi.Mode().Perm())
	}
	return os.Rename(tmp.Name(), path)
}

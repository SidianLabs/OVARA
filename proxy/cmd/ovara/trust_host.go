package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// trustReadHost adds "GET/HEAD https://<host>/*" allow rules to policy.json,
// at the front, unless they are already there. The gateway reloads the file
// on its own. The write is atomic (temp file + rename).
func trustReadHost(dir, host string) (added bool, err error) {
	path := filepath.Join(dir, "policy.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	rules, _ := doc["rules"].([]any)
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
				"action_type": "http.request", "environment": "*", "resource": resource,
				"allow": true, "description": "Trusted for reads from the approval prompt: " + host,
			})
		}
	}
	if len(fresh) == 0 {
		return false, nil
	}
	doc["rules"] = append(fresh, rules...)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if fi, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmp.Name(), fi.Mode().Perm())
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}

// Package creds holds credential bindings: which real headers get injected
// for which upstream hosts. Secret values are expanded from the proxy
// host's environment at load time — they never enter the agent's env.
package creds

import (
	"os"
	"path"
	"strings"
)

type Binding struct {
	Host    string            `json:"host"`    // glob like "api.github.com" or "*.openai.com"
	Headers map[string]string `json:"headers"` // header -> value, ${ENV} expanded at load
}

// Load expands ${ENV_VAR} placeholders in header values. A binding whose
// variables are not all set is dropped (see LoadReport).
func Load(bindings []Binding) []Binding {
	out, _ := LoadReport(bindings)
	return out
}

// Skipped describes a binding that was not loaded because a variable it
// needs is unset or empty.
type Skipped struct {
	Host    string
	Missing []string
}

// LoadReport expands ${ENV_VAR} placeholders and reports bindings it had
// to drop. Injecting a binding with an unset variable would replace the
// agent's own (possibly working) header with "Bearer " or an empty key,
// breaking requests that would otherwise succeed. A dropped binding means
// the agent's own headers pass through unchanged for that host.
func LoadReport(bindings []Binding) ([]Binding, []Skipped) {
	out := make([]Binding, 0, len(bindings))
	var skipped []Skipped
	for _, b := range bindings {
		h := make(map[string]string, len(b.Headers))
		var missing []string
		for k, v := range b.Headers {
			h[k] = os.Expand(v, func(name string) string {
				val := os.Getenv(name)
				if val == "" {
					missing = append(missing, name)
				}
				return val
			})
		}
		if len(missing) > 0 {
			skipped = append(skipped, Skipped{Host: b.Host, Missing: missing})
			continue
		}
		out = append(out, Binding{Host: b.Host, Headers: h})
	}
	return out, skipped
}

// Match returns the headers to inject for an upstream host, or nil.
// Host match is exact or path.Match-style glob ("*.openai.com").
func Match(bindings []Binding, host string) map[string]string {
	host = strings.ToLower(host)
	for _, b := range bindings {
		pat := strings.ToLower(b.Host)
		if pat == host {
			return b.Headers
		}
		if ok, _ := path.Match(pat, host); ok {
			return b.Headers
		}
	}
	return nil
}

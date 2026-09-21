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

// Load expands ${ENV_VAR} placeholders in header values.
func Load(bindings []Binding) []Binding {
	out := make([]Binding, 0, len(bindings))
	for _, b := range bindings {
		h := make(map[string]string, len(b.Headers))
		for k, v := range b.Headers {
			h[k] = os.ExpandEnv(v)
		}
		out = append(out, Binding{Host: b.Host, Headers: h})
	}
	return out
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

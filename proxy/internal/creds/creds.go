// Package creds holds credential bindings: which real headers get injected
// for which upstream hosts. Secret values are expanded from the proxy
// host's environment at load time — they never enter the agent's env.
package creds

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"
)

// Binding attaches headers to requests for one host. Host alone binds every
// request to that host on port 443; Paths and Methods narrow it to the
// requests a task needs, so a token that can reach every repository is only
// sent for the one being worked on.
type Binding struct {
	// Host is a glob like "api.github.com" or "*.openai.com", optionally
	// with a port ("git.example.com:8443"). Without a port it matches 443
	// only: a credential for a host is not handed to whatever else that
	// host runs on another port.
	Host string `json:"host"`
	// Paths, when set, limit the binding to URL paths matching one of these
	// globs ("/repos/acme/app", "/repos/acme/app/*"). '*' matches any run
	// of characters, '/' included. Matching is on the decoded path and is
	// case-sensitive; a path with "." or ".." segments never matches.
	Paths []string `json:"paths,omitempty"`
	// Methods, when set, limit the binding to these HTTP methods.
	Methods []string          `json:"methods,omitempty"`
	Headers map[string]string `json:"headers,omitempty"` // header -> value, ${ENV} expanded at load

	// GitHubApp and OAuth2 make the binding a broker (broker.go): instead
	// of a fixed header it injects a short-lived token minted from a
	// long-lived secret that stays in Ovara's environment. At most one.
	GitHubApp *GitHubApp `json:"github_app,omitempty"`
	OAuth2    *OAuth2    `json:"oauth2,omitempty"`

	broker *broker // set by LoadReport for a brokered binding
}

// MinSecretLen is the shortest secret a binding may inject. The response
// scrubber cannot redact shorter values without corrupting ordinary text,
// so a binding that would inject one is refused at load.
const MinSecretLen = 8

// nonSecretHeaders are the only injected headers whose values are not
// treated as secrets (not scrubbed from responses, not length-checked).
// Exact names only: a name merely containing "version" is still a secret.
var nonSecretHeaders = map[string]bool{
	"anthropic-version":    true,
	"x-github-api-version": true,
	"content-type":         true,
	"accept":               true,
	"user-agent":           true,
}

// NonSecretHeader reports whether an injected header carries protocol
// metadata rather than a credential.
func NonSecretHeader(name string) bool {
	return nonSecretHeaders[strings.ToLower(name)]
}

// Load expands ${ENV_VAR} placeholders in header values. Bindings that
// LoadReport drops or refuses are left out; callers that can stop startup
// should use LoadReport and act on its error.
func Load(bindings []Binding) []Binding {
	out, _, _ := LoadReport(bindings)
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
//
// The error is for bindings that must stop startup instead: a secret from
// the environment shorter than MinSecretLen (it could not be scrubbed from
// responses), or a malformed host or path. The bindings returned alongside
// an error leave the offending ones out.
func LoadReport(bindings []Binding) ([]Binding, []Skipped, error) {
	out := make([]Binding, 0, len(bindings))
	var skipped []Skipped
	var errs []string
	for _, b := range bindings {
		if err := b.validate(); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		h := make(map[string]string, len(b.Headers))
		var missing, short []string
		for k, v := range b.Headers {
			secret := !NonSecretHeader(k)
			expanded := false
			h[k] = os.Expand(v, func(name string) string {
				expanded = true
				val := os.Getenv(name)
				if val == "" {
					missing = append(missing, name)
				} else if secret && len(val) < MinSecretLen {
					short = append(short, name)
				}
				return val
			})
			if secret && expanded && h[k] != "" {
				// The part after an auth scheme ("Bearer ${A}${B}") is
				// what a reflector echoes; it must be long enough too.
				tok := h[k]
				if _, t, ok := strings.Cut(tok, " "); ok {
					tok = t
				}
				if len(tok) < MinSecretLen && len(short) == 0 {
					short = append(short, "the value of "+k)
				}
			}
		}
		var br *broker
		if b.Brokered() {
			e := &expander{}
			nbr, err := loadBroker(b, e)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			missing = append(missing, e.missing...)
			br = nbr
		}
		if len(missing) > 0 {
			skipped = append(skipped, Skipped{Host: b.Host, Missing: missing})
			continue
		}
		if len(short) > 0 {
			errs = append(errs, fmt.Sprintf("credential for %s: %s is shorter than %d bytes; a key that short cannot be kept out of responses, so it is refused (set the real key, or remove the binding)",
				b.Host, strings.Join(short, ", "), MinSecretLen))
			continue
		}
		nb := b
		nb.Headers = h
		nb.broker = br
		out = append(out, nb)
	}
	out = append(out, gitCompanions(bindings, out)...)
	if len(errs) > 0 {
		return out, skipped, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, skipped, nil
}

func (b Binding) validate() error {
	host, _ := splitHostPattern(b.Host)
	if host == "" {
		return fmt.Errorf("credential binding with an empty host")
	}
	if _, err := path.Match(host, ""); err != nil {
		return fmt.Errorf("credential binding host %q: %v", b.Host, err)
	}
	for _, p := range b.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("credential binding for %s: path %q must start with '/'", b.Host, p)
		}
	}
	return nil
}

// splitHostPattern splits "host[:port]" into its lower-case host glob and
// port, defaulting the port to 443.
func splitHostPattern(pat string) (string, string) {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if h, p, err := net.SplitHostPort(pat); err == nil {
		return h, p
	}
	return pat, "443"
}

// Request is what a binding is matched against. Port is the port the
// request goes to ("" means 443); Path is the decoded URL path.
type Request struct {
	Host, Port, Method, Path string
}

// gitCompanions returns, for a GitHub App binding on api.github.com, the
// same broker bound to github.com (git smart-HTTP, where the token goes as
// Basic x-access-token), unless the configuration binds github.com itself.
func gitCompanions(configured, loaded []Binding) []Binding {
	for _, b := range configured {
		if h, p := splitHostPattern(b.Host); h == "github.com" && p == "443" {
			return nil
		}
	}
	for _, b := range loaded {
		if h, p := splitHostPattern(b.Host); h != "api.github.com" || p != "443" || b.GitHubApp == nil || b.broker == nil {
			continue
		}
		return []Binding{{Host: "github.com", GitHubApp: b.GitHubApp, broker: b.broker}}
	}
	return nil
}

// Match returns the headers to inject for an upstream host on port 443,
// considering only bindings that are not narrowed by path or method.
func Match(bindings []Binding, host string) map[string]string {
	return MatchRequest(bindings, Request{Host: host})
}

// MatchRequest returns the headers to inject for a request, or nil. The
// first binding whose host, port, method and path all match wins. Host
// match is exact or path.Match-style glob ("*.openai.com").
//
// For a brokered binding these are only its fixed headers; use
// MatchBinding and Binding.Credential to get the minted token.
func MatchRequest(bindings []Binding, req Request) map[string]string {
	if b := MatchBinding(bindings, req); b != nil {
		return b.Headers
	}
	return nil
}

// MatchBinding returns the first binding whose host, port, method and path
// all match the request, or nil.
func MatchBinding(bindings []Binding, req Request) *Binding {
	host := strings.ToLower(req.Host)
	port := req.Port
	if port == "" {
		port = "443"
	}
	for i := range bindings {
		b := &bindings[i]
		pat, bport := splitHostPattern(b.Host)
		if bport != port {
			continue
		}
		if pat != host {
			if ok, _ := path.Match(pat, host); !ok {
				continue
			}
		}
		if !matchMethod(b.Methods, req.Method) || !matchPath(b.Paths, req.Path) {
			continue
		}
		return b
	}
	return nil
}

func matchMethod(methods []string, m string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, x := range methods {
		if m != "" && strings.EqualFold(x, m) {
			return true
		}
	}
	return false
}

func matchPath(globs []string, p string) bool {
	if len(globs) == 0 {
		return true
	}
	// Dot segments would let a path that matches the glob name a resource
	// outside it once the upstream resolves them.
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for _, g := range globs {
		if glob(g, p) {
			return true
		}
	}
	return false
}

// glob matches s against pattern where '*' matches any run of characters,
// '/' included (the meaning '*' has in policy rules).
func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// ScopeToRepo returns bindings with every binding for host narrowed to one
// repository: on an API host ("api.github.com") the "/repos/<owner>/<repo>"
// tree, on a git host ("github.com") the repository's web and smart-HTTP
// paths. A binding that already lists paths keeps only those inside the
// repository and is dropped if none are left. Bindings for other hosts are
// returned unchanged; the input is not modified.
//
// Requests outside the tree (other repositories, the account, GraphQL)
// then go out without the credential.
//
// An owner or repo that is not a plain GitHub name (see RepoName) would
// put a glob or another path segment into the scope ("*" would cover every
// repository); every binding for host is then dropped instead.
func ScopeToRepo(bindings []Binding, host, owner, repo string) []Binding {
	host = strings.ToLower(host)
	if !RepoName(owner) || !RepoName(repo) {
		out := make([]Binding, 0, len(bindings))
		for _, b := range bindings {
			if pat, _ := splitHostPattern(b.Host); pat != host {
				out = append(out, b)
			}
		}
		return out
	}
	var roots []string
	if strings.HasPrefix(host, "api.") {
		roots = []string{"/repos/" + owner + "/" + repo}
	} else {
		roots = []string{"/" + owner + "/" + repo, "/" + owner + "/" + repo + ".git"}
	}
	scope := make([]string, 0, 2*len(roots))
	for _, r := range roots {
		scope = append(scope, r, r+"/*")
	}
	out := make([]Binding, 0, len(bindings))
	for _, b := range bindings {
		if pat, _ := splitHostPattern(b.Host); pat != host {
			out = append(out, b)
			continue
		}
		nb := b
		nb.Headers = make(map[string]string, len(b.Headers))
		for k, v := range b.Headers {
			nb.Headers[k] = v
		}
		nb.Methods = append([]string(nil), b.Methods...)
		if len(b.Paths) == 0 {
			nb.Paths = append([]string(nil), scope...)
		} else {
			nb.Paths = nil
			for _, p := range b.Paths {
				if within(p, roots) {
					nb.Paths = append(nb.Paths, p)
				}
			}
			if len(nb.Paths) == 0 {
				continue
			}
		}
		out = append(out, nb)
	}
	return out
}

// within reports whether every path the glob p can match lies inside one
// of the repository trees: its literal head is a root exactly (no '*'),
// or a root followed by "/".
func within(p string, roots []string) bool {
	head, _, wild := strings.Cut(p, "*")
	for _, r := range roots {
		if strings.HasPrefix(head, r+"/") || (!wild && head == r) {
			return true
		}
	}
	return false
}

// RepoName reports whether s can be a GitHub owner or repository name:
// letters, digits, '-', '_' and '.', and not "." or "..". Nothing else may
// reach a credential scope, where '*' is a glob and '/' a path segment.
func RepoName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

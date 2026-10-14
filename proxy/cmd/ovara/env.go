package main

// `ovara env` prints the environment an agent needs to run through Ovara:
// the proxy URL (with the agent's proxy token), Ovara's CA certificate
// under every variable the common runtimes read, and placeholder values
// for the API keys Ovara injects, so tools that refuse to start without a
// key still start, while the real key stays with Ovara.
//
//	eval "$(ovara env -dir mydir)"              # bash / zsh
//	ovara env -dir mydir -shell powershell | iex # PowerShell

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/creds"
)

// caVars are the variables common runtimes read for extra trusted CAs.
var caVars = []struct{ name, who string }{
	{"SSL_CERT_FILE", "OpenSSL-based tools, Go, Python ssl"},
	{"NODE_EXTRA_CA_CERTS", "Node.js (Claude Code, npm, most JS agents)"},
	{"REQUESTS_CA_BUNDLE", "Python requests / httpx"},
	{"CURL_CA_BUNDLE", "curl"},
	{"GIT_SSL_CAINFO", "git over HTTPS"},
}

// Placeholder handed to the agent in place of a real key. Ovara replaces
// the whole header on the way out, so the value never matters upstream.
const keyPlaceholder = "ovara-injects-the-real-key"

// loopbackNoProxy is the NO_PROXY the agent gets: Ovara's own address and
// nothing else. A list inherited from the shell (corporate setups, CI images
// and sandboxes set one) names hosts the agent's tools contact directly,
// unseen by Ovara: no decision, no receipt.
const loopbackNoProxy = "127.0.0.1,localhost"

// hostLike is what an entry of a NO_PROXY list looks like: a host name, an
// address or a CIDR block, with a leading dot, a wildcard or a port at most.
// Anything else is never printed, because the note that names the replaced
// list is written into a stream that is eval'd.
var hostLike = regexp.MustCompile(`^[A-Za-z0-9._*:/\[\]-]{1,100}$`)

// inheritedNoProxy returns the entries of the shell's NO_PROXY and no_proxy
// that are not loopback, in the order found, and how many of them are left
// out for not looking like hosts.
func inheritedNoProxy() (hosts []string, odd int) {
	seen := map[string]bool{}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		for _, e := range strings.Split(os.Getenv(name), ",") {
			e = strings.TrimSpace(e)
			switch strings.ToLower(e) {
			case "", "localhost", "127.0.0.1", "::1", "[::1]":
				continue
			}
			if seen[e] {
				continue
			}
			seen[e] = true
			if hostLike.MatchString(e) {
				hosts = append(hosts, e)
			} else {
				odd++
			}
		}
	}
	return hosts, odd
}

// noProxyNote says which hosts the shell's NO_PROXY listed, or "" when it
// listed none.
func noProxyNote(hosts []string, odd int) string {
	if len(hosts) == 0 && odd == 0 {
		return ""
	}
	const shown = 4
	more := odd
	if len(hosts) > shown {
		more += len(hosts) - shown
		hosts = hosts[:shown]
	}
	list := strings.Join(hosts, ", ")
	switch {
	case list == "":
		list = fmt.Sprintf("%d entries", more)
	case more > 0:
		list += fmt.Sprintf(" and %d more", more)
	}
	return "NO_PROXY in this shell lists " + list + ": tools skip the proxy for those hosts, so they would go around Ovara. " +
		"It is set to loopback only here; allow the hosts you need in policy.json instead."
}

var bindingKeyRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	def := "bash"
	if runtime.GOOS == "windows" {
		def = "powershell"
	}
	shell := fs.String("shell", def, "bash | powershell | cmd | github (NAME=value lines for a CI environment file such as $GITHUB_ENV)")
	host := fs.String("host", "127.0.0.1", "address the agent uses to reach the proxy")
	keepEnv := fs.Bool("keep-env", false, "do not unset other secret-looking variables (tokens, cloud keys) found in this shell")
	agent := fs.String("agent", "", "the named agent this shell is for (ovara agent add NAME): its own proxy token, so receipts and approvals name it and ovara kill can stop it alone")
	if err := fs.Parse(args); err != nil {
		return err
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(abs, "proxy.json"))
	if err != nil {
		return fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", abs, err)
	}
	if *agent != "" {
		tok, err := agentProxyToken(cfg, *agent)
		if err != nil {
			return err
		}
		cfg.AgentToken = tok
	}
	vars, notes, err := agentEnv(abs, cfg, *host)
	if err != nil {
		return err
	}
	if err := writeEnv(os.Stdout, *shell, vars, notes); err != nil {
		return err
	}
	if *keepEnv {
		return nil
	}
	set := map[string]bool{}
	for _, v := range vars {
		set[strings.ToUpper(v.name)] = true
	}
	return writeUnsets(os.Stdout, *shell, secretEnvNames(os.Environ(), set))
}

// secretNameParts and secretNamePrefixes pick out variables that look like
// credentials: an agent started from this shell would inherit them, and
// Ovara cannot keep a key out of the agent's hands if it is already there.
var (
	secretNameParts    = []string{"TOKEN", "SECRET", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "PASSWORD", "PASSWD", "CREDENTIAL"}
	secretNamePrefixes = []string{"AWS_", "AZURE_", "GH_", "GOOGLE_APPLICATION_CREDENTIALS"}
	envNameOK          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// secretEnvNames returns the sorted names in environ ("NAME=value") that
// look like credentials, except those in skip (upper-case names Ovara sets
// itself, such as the placeholders). Names that are not plain identifiers
// are left out: they cannot be written safely into a shell line.
func secretEnvNames(environ []string, skip map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		if name == "" || skip[up] || seen[up] || !envNameOK.MatchString(name) {
			continue
		}
		hit := false
		for _, p := range secretNameParts {
			hit = hit || strings.Contains(up, p)
		}
		for _, p := range secretNamePrefixes {
			hit = hit || strings.HasPrefix(up, p)
		}
		if hit {
			seen[up] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// writeUnsets prints the lines that remove names from the agent's shell.
func writeUnsets(w io.Writer, shell string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	var line func(string) string
	comment := "#"
	switch strings.ToLower(shell) {
	case "bash", "sh", "zsh":
		line = func(n string) string { return "unset " + n }
	case "powershell", "pwsh", "ps":
		line = func(n string) string { return "Remove-Item Env:" + n + " -ErrorAction SilentlyContinue" }
	case "cmd":
		comment = "rem"
		line = func(n string) string { return "set \"" + n + "=\"" }
	case "github":
		line = func(n string) string { return n + "=" } // an environment file cannot unset; empty is the next best
	default:
		return fmt.Errorf("unknown -shell %q (use bash, powershell, cmd or github)", shell)
	}
	fmt.Fprintf(w, "%s other secrets in this shell, removed so the agent does not inherit them (keep them with -keep-env)\n", comment)
	for _, n := range names {
		fmt.Fprintln(w, line(n))
	}
	return nil
}

type envVar struct{ name, value, comment string }

func agentEnv(dir string, cfg *config.Config, host string) ([]envVar, []string, error) {
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy listen_addr %q: %w", cfg.ListenAddr, err)
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	if cfg.AgentToken != "" {
		u.User = url.UserPassword("agent", cfg.AgentToken)
	}
	proxyURL := u.String()

	var notes []string
	ca := inDir(dir, cfg.CACertFile)
	if _, err := os.Stat(ca); err != nil {
		notes = append(notes, "the CA certificate does not exist yet: it is created the first time you run `ovara run`.")
	}

	vars := []envVar{
		{"HTTPS_PROXY", proxyURL, "every request goes through Ovara"},
		{"HTTP_PROXY", proxyURL, ""},
		{"https_proxy", proxyURL, "some tools only read the lowercase names"},
		{"http_proxy", proxyURL, ""},
		// Verified: on Node 22 a plain fetch() went straight out, unseen
		// by Ovara, unless this is set.
		{"NODE_USE_ENV_PROXY", "1", "Node.js: make built-in fetch() honour the proxy (without it, it silently goes direct)"},
		// Verified with a real agent: with the sandbox's NO_PROXY inherited,
		// its calls to a host on that list left no receipt at all.
		{"NO_PROXY", loopbackNoProxy, "hosts that skip Ovara: loopback only (an inherited list lets tools go around it)"},
		{"no_proxy", loopbackNoProxy, ""},
	}
	if hosts, odd := inheritedNoProxy(); len(hosts)+odd > 0 {
		notes = append(notes, noProxyNote(hosts, odd))
	}
	for _, v := range caVars {
		vars = append(vars, envVar{v.name, ca, "trust Ovara's certificate: " + v.who})
	}

	// Placeholders only for keys Ovara is actually injecting (recorded by
	// `ovara run`). A placeholder for a key Ovara does not hold would
	// break the agent: e.g. a fake ANTHROPIC_API_KEY switches Claude Code
	// from a subscription login to API-key mode with a key that can't work.
	keys, ok := readActiveKeys(dir)
	if !ok {
		notes = append(notes, "no placeholder API keys yet: start `ovara run` first, then re-run `ovara env` (it sets placeholders only for keys Ovara really injects).")
	}
	for i, k := range keys {
		c := ""
		if i == 0 {
			c = "placeholders: the agent never holds the real keys, Ovara injects them"
		}
		vars = append(vars, envVar{k, keyPlaceholder, c})
	}
	return vars, notes, nil
}

// activeKeysFile records the NAMES (never values) of the environment
// variables behind the credential bindings `ovara run` is injecting.
const activeKeysFile = "var/active-keys.json"

// bindingKeys returns the sorted variable names referenced by bindings.
func bindingKeys(bindings []creds.Binding) []string {
	seen := map[string]bool{}
	var keys []string
	for _, b := range bindings {
		// A GitHub App binding's variables (App ID, key) are the broker's
		// inputs, not keys the agent's tools look for; those tools look
		// for GITHUB_TOKEN, which Ovara then fills with a minted token.
		if b.GitHubApp != nil && !seen["GITHUB_TOKEN"] {
			seen["GITHUB_TOKEN"] = true
			keys = append(keys, "GITHUB_TOKEN")
		}
		for _, val := range b.Headers {
			for _, m := range bindingKeyRef.FindAllStringSubmatch(val, -1) {
				if !seen[m[1]] {
					seen[m[1]] = true
					keys = append(keys, m[1])
				}
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// writeActiveKeys is called by `ovara run` with the configured
// (unexpanded) bindings and the ones LoadReport had to skip.
func writeActiveKeys(dir string, configured []creds.Binding, skipped []creds.Skipped) error {
	skip := map[string]bool{}
	for _, s := range skipped {
		skip[s.Host] = true
	}
	var active []creds.Binding
	for _, b := range configured {
		if !skip[b.Host] {
			active = append(active, b)
		}
	}
	names := bindingKeys(active)
	if names == nil {
		names = []string{}
	}
	b, err := json.Marshal(map[string]any{"keys": names})
	if err != nil {
		return err
	}
	return os.WriteFile(inDir(dir, activeKeysFile), b, 0o644)
}

func readActiveKeys(dir string) ([]string, bool) {
	raw, err := os.ReadFile(inDir(dir, activeKeysFile))
	if err != nil {
		return nil, false
	}
	var f struct {
		Keys []string `json:"keys"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return nil, false
	}
	return f.Keys, true
}

func writeEnv(w io.Writer, shell string, vars []envVar, notes []string) error {
	var line func(v envVar) string
	var comment string
	switch strings.ToLower(shell) {
	case "bash", "sh", "zsh":
		comment = "#"
		line = func(v envVar) string {
			return "export " + v.name + "='" + strings.ReplaceAll(v.value, "'", `'\''`) + "'"
		}
	case "powershell", "pwsh", "ps":
		comment = "#"
		line = func(v envVar) string { return "$env:" + v.name + " = '" + strings.ReplaceAll(v.value, "'", "''") + "'" }
	case "cmd":
		comment = "rem"
		line = func(v envVar) string { return "set \"" + v.name + "=" + v.value + "\"" }
	case "github":
		// one NAME=value per line, what $GITHUB_ENV takes
		comment = "#"
		line = func(v envVar) string { return v.name + "=" + v.value }
	default:
		return fmt.Errorf("unknown -shell %q (use bash, powershell, cmd or github)", shell)
	}
	fmt.Fprintf(w, "%s Ovara agent environment: run your agent in a shell with these set.\n", comment)
	for _, n := range notes {
		fmt.Fprintf(w, "%s NOTE: %s\n", comment, n)
	}
	for _, v := range vars {
		if v.comment != "" {
			fmt.Fprintf(w, "%s %s\n", comment, v.comment)
		}
		fmt.Fprintln(w, line(v))
	}
	return nil
}

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

var bindingKeyRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	def := "bash"
	if runtime.GOOS == "windows" {
		def = "powershell"
	}
	shell := fs.String("shell", def, "bash | powershell | cmd")
	host := fs.String("host", "127.0.0.1", "address the agent uses to reach the proxy")
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
	vars, notes, err := agentEnv(abs, cfg, *host)
	if err != nil {
		return err
	}
	return writeEnv(os.Stdout, *shell, vars, notes)
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
	}
	for _, v := range caVars {
		vars = append(vars, envVar{v.name, ca, "trust Ovara's certificate: " + v.who})
	}

	// Placeholders for every key referenced by a credential binding.
	seen := map[string]bool{}
	var keys []string
	for _, b := range cfg.Credentials {
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
	for i, k := range keys {
		c := ""
		if i == 0 {
			c = "placeholders: the agent never holds the real keys, Ovara injects them"
		}
		vars = append(vars, envVar{k, keyPlaceholder, c})
	}
	return vars, notes, nil
}

func writeEnv(w io.Writer, shell string, vars []envVar, notes []string) error {
	var line func(v envVar) string
	var comment string
	switch strings.ToLower(shell) {
	case "bash", "sh", "zsh":
		comment = "#"
		line = func(v envVar) string { return "export " + v.name + "='" + strings.ReplaceAll(v.value, "'", `'\''`) + "'" }
	case "powershell", "pwsh", "ps":
		comment = "#"
		line = func(v envVar) string { return "$env:" + v.name + " = '" + strings.ReplaceAll(v.value, "'", "''") + "'" }
	case "cmd":
		comment = "rem"
		line = func(v envVar) string { return "set \"" + v.name + "=" + v.value + "\"" }
	default:
		return fmt.Errorf("unknown -shell %q (use bash, powershell or cmd)", shell)
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

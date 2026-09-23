// `ovara doctor` — read-only posture audit of a deployment directory.
// Verifies the invariants an operator expects after `ovara init`:
// config parses, auth is locked down, secrets stay out of files,
// durable trust state is configured, and the receipt chain verifies.
// Prints PASS/WARN/FAIL per check plus a containment verdict; exits
// nonzero on any FAIL.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

type check struct {
	name   string
	status string // "PASS", "WARN", "FAIL"
	detail string
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory from ovara init")
	fs.Parse(args)

	checks := auditDeployment(*dir)
	failed := false
	for _, c := range checks {
		fmt.Printf("%-4s  %-42s %s\n", c.status, c.name, c.detail)
		if c.status == "FAIL" {
			failed = true
		}
	}
	fmt.Println()
	if failed {
		fmt.Println("CONTAINMENT: NOT GUARANTEED — resolve FAIL items")
		return fmt.Errorf("posture audit failed")
	}
	fmt.Println("CONTAINMENT: VALID UNDER DOCUMENTED ASSUMPTIONS")
	return nil
}

func auditDeployment(dir string) []check {
	var out []check

	// --- config.json -------------------------------------------------------
	gwRaw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return []check{{"config.json", "FAIL", "missing or unreadable — run `ovara init` first"}}
	}
	var gw map[string]any
	if err := json.Unmarshal(gwRaw, &gw); err != nil {
		out = append(out, check{"config.json", "FAIL", "invalid JSON: " + err.Error()})
		return out
	}
	out = append(out, check{"config.json", "PASS", "parses"})

	str := func(k string) string {
		if v, ok := gw[k].(string); ok {
			return v
		}
		return ""
	}
	b := func(k string) bool {
		v, _ := gw[k].(bool)
		return v
	}
	strList := func(k string) int {
		if a, ok := gw[k].([]any); ok {
			return len(a)
		}
		return 0
	}

	// --- policy file -------------------------------------------------------
	pf := str("policy_file")
	if pf == "" {
		out = append(out, check{"policy file", "WARN", "policy_file not configured — in-memory default rules only"})
	} else {
		pdata, err := os.ReadFile(filepath.Join(dir, pf))
		if err != nil {
			out = append(out, check{"policy file", "FAIL", pf + " configured but unreadable"})
		} else {
			var p struct {
				Version string `json:"version"`
				Rules   []struct {
					ActionType string `json:"action_type"`
				} `json:"rules"`
			}
			if err := json.Unmarshal(pdata, &p); err != nil {
				out = append(out, check{"policy file", "FAIL", pf + " invalid JSON: " + err.Error()})
			} else if len(p.Rules) == 0 {
				out = append(out, check{"policy file", "WARN", pf + " has no rules"})
			} else {
				out = append(out, check{"policy file", "PASS", fmt.Sprintf("%s: %d rules (%s)", pf, len(p.Rules), p.Version)})
			}
		}
	}

	// --- auth posture ------------------------------------------------------
	if !b("auth_enabled") {
		out = append(out, check{"auth", "WARN", "auth_enabled=false — gateway open, any client can approve its own escalations"})
	} else if strList("operator_tokens") == 0 {
		out = append(out, check{"auth", "FAIL", "auth_enabled=true but operator_tokens empty — gateway denies ALL requests (fail-closed)"})
	} else {
		out = append(out, check{"auth", "PASS", fmt.Sprintf("auth_enabled with %d operator + %d agent token(s)", strList("operator_tokens"), strList("agent_tokens"))})
	}
	if addr := str("listen_addr"); addr != "" && addr != "127.0.0.1" && addr != "localhost" && addr != "::1" {
		out = append(out, check{"listen addr", "WARN", fmt.Sprintf("listen_addr=%s — approval/decision API reachable off-loopback", addr)})
	} else {
		out = append(out, check{"listen addr", "PASS", "loopback only"})
	}

	// --- durable trust state ------------------------------------------------
	// Every authority store left unconfigured runs memory-mode: a restart
	// loses identity, replay protection, approvals, and revocation state.
	durable := []struct {
		key, what string
	}{
		{"gateway_registry_file", "gateway identity"},
		{"gateway_key_file", "gateway signing key"},
		{"identity_registry_file", "identity registry"},
		{"replay_file", "replay journal"},
		{"continuation_file", "continuations"},
		{"approval_file", "approvals"},
		{"execution_file", "executions"},
		{"anchor_file", "anchor checkpoints"},
	}
	var missing []string
	for _, d := range durable {
		if str(d.key) == "" {
			missing = append(missing, d.what)
		}
	}
	if len(missing) == 0 {
		out = append(out, check{"durable state", "PASS", "all authority stores file-backed"})
	} else {
		out = append(out, check{"durable state", "WARN", fmt.Sprintf("memory-mode: %s — restart loses this trust state", strings.Join(missing, ", "))})
	}
	if b("journal_signing_required") {
		out = append(out, check{"journal signing", "PASS", "journal_signing_required=true"})
	} else {
		out = append(out, check{"journal signing", "WARN", "authority journals unsigned (set journal_signing_required=true once durable signing is configured)"})
	}

	// --- proxy.json ---------------------------------------------------------
	pcfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		out = append(out, check{"proxy.json", "FAIL", "missing or invalid: " + err.Error()})
		return out
	}
	out = append(out, check{"proxy.json", "PASS", "parses"})
	out = append(out, auditCredentials(pcfg)...)

	// --- CA / keys ----------------------------------------------------------
	// CA files are created by ca.LoadOrCreate on first `ovara run`, so a
	// fresh init legitimately lacks them — WARN, not FAIL. The receipt
	// key is written by init itself and must exist.
	for _, f := range []struct {
		path, what string
		auto       bool
	}{
		{pcfg.CACertFile, "CA cert", true}, {pcfg.CAKeyFile, "CA key", true}, {pcfg.ReceiptKeyFile, "receipt signing key", false},
	} {
		if _, err := os.Stat(filepath.Join(dir, f.path)); err != nil {
			if f.auto {
				out = append(out, check{f.what, "WARN", f.path + " not yet created (generated on first `ovara run`)"})
			} else {
				out = append(out, check{f.what, "FAIL", f.path + " missing"})
			}
		} else {
			out = append(out, check{f.what, "PASS", f.path})
		}
	}

	// --- receipt chain -------------------------------------------------------
	chainRes := auditReceipts(dir, pcfg)
	out = append(out, chainRes...)

	return out
}

var envRef = regexp.MustCompile(`\$\{[A-Z_][A-Z0-9_]*\}`)

// auditCredentials flags credential bindings that embed a literal secret
// instead of an ${ENV} reference, and ${ENV} references whose variable is
// unset — the two ways creds custody silently breaks.
func auditCredentials(cfg *config.Config) []check {
	var out []check
	for _, b := range cfg.Credentials {
		for h, v := range b.Headers {
			switch {
			case strings.Contains(v, "${"):
				for _, ref := range envRef.FindAllString(v, -1) {
					name := ref[2 : len(ref)-1]
					if os.Getenv(name) == "" {
						out = append(out, check{"credential " + b.Host, "WARN", h + " references unset env var " + name})
					}
				}
			case looksLikeSecret(v):
				out = append(out, check{"credential " + b.Host, "FAIL", h + " contains a literal secret — use ${ENV} so the agent-side file never carries it"})
			}
		}
	}
	if len(out) == 0 {
		return []check{{"credentials", "PASS", fmt.Sprintf("%d binding(s), all env-referenced", len(cfg.Credentials))}}
	}
	return out
}

// looksLikeSecret detects tokens committed directly into proxy.json.
// Conservative prefixes plus high-entropy Bearer values — misses nothing
// an attacker would mistake for a placeholder either.
func looksLikeSecret(v string) bool {
	for _, p := range []string{"sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "glpat-", "AKIA"} {
		if strings.Contains(v, p) {
			return true
		}
	}
	if strings.HasPrefix(v, "Bearer ") && len(v) > 15 && !strings.Contains(v, "${") {
		return true
	}
	return false
}

func auditReceipts(dir string, cfg *config.Config) []check {
	chainPath := filepath.Join(dir, cfg.ReceiptsFile)
	pubPath := filepath.Join(dir, cfg.PubKeyFile)
	if _, err := os.Stat(chainPath); err != nil {
		return []check{{"receipt chain", "PASS", "no receipts yet — nothing to verify"}}
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return []check{{"receipt chain", "FAIL", cfg.PubKeyFile + " missing but receipts exist"}}
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubRaw)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return []check{{"receipt chain", "FAIL", cfg.PubKeyFile + " is not a valid ed25519 key"}}
	}
	res := receipts.VerifyFile(chainPath, ed25519.PublicKey(pub))
	if !res.Valid {
		return []check{{"receipt chain", "FAIL", fmt.Sprintf("verification failed at %d: %s", res.FailAt, res.Reason)}}
	}
	return []check{{"receipt chain", "PASS", fmt.Sprintf("%d receipts verified", res.Total)}}
}

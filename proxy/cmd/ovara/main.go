// Ovara is the unified CLI for a local deployment: one binary that
// generates a working gateway+proxy configuration (init), runs both
// halves (run), and proves the loop end-to-end (demo).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/lockfiles"
	"ovara.proxy/internal/proxy"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/scripts"
	"ovara.runtime.gateway/pkg/server"
)

// version is stamped by release builds: -ldflags "-X main.version=v0.10.0".
var version = "dev"

// boxInitCmd is the subcommand a box runs as its first program (tier 1) or
// PID 1 (tier 2); people do not run it.
const boxInitCmd = "box-init"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println("ovara", version)
		return
	case "init":
		err = cmdInit(os.Args[2:])
	case "box":
		err = cmdBox(os.Args[2:])
	case boxInitCmd: // PID 1 of a tier 2 box; started by `ovara box -tier 2`, not by people
		err = cmdBoxInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "demo":
		err = cmdDemo()
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "log":
		err = cmdLog(os.Args[2:])
	case "incident":
		err = cmdIncident(os.Args[2:])
	case "keys":
		err = cmdKeys(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "approvals":
		err = cmdApprovals(os.Args[2:])
	case "approve":
		err = cmdResolve(true, os.Args[2:])
	case "deny":
		err = cmdResolve(false, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: ovara <command>

  version               print the ovara version
  init [dir] [-force]   generate a working gateway+proxy deployment
  run [-dir .]          start the gateway and the executor proxy
  box <dir> -- <agent>  run an agent in a box: a copy of the project, no keys,
                        no network except through Ovara; changes come back as a
                        reviewed branch (Linux, sudo)
  demo                  self-contained end-to-end demo (no network, no root)
  env [-dir .]          print the environment to run your agent through Ovara
  policy [-dir .]       explain the rules in plain English
  policy test "<METHOD URL>"  what would happen if the agent did this (dry run)
  watch [-dir .]        answer approval requests live: approve / deny each one
  approvals [-dir .]    list agent requests waiting for approval
  log [-dir .] [-n 50]  what the agent did (allowed/approved/blocked), integrity-checked
  log -verify-only      only check the receipt chain (also -receipts F -pubkey F for copies)
  log export [-format jsonl|ocsf] [-since T]   verified receipts for a SIEM
  incident bundle -out F.tar.gz [-since T]     receipts, anchors, keys and policy to check offline
  keys rotate-receipt | revoke-receipt -key K | list-receipt   manage the receipt signing key
  approve <id>          let a waiting request through
  deny <id>             block a waiting request
  doctor [-dir .]       audit deployment posture (config, auth, custody, receipts)`)
}

// --- init -----------------------------------------------------------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite existing files (an existing var/receipt.key is always kept)")
	fs.Parse(args)
	dir := fs.Arg(0)
	if dir == "" {
		dir = "."
	}
	if _, err := deploy(dir, "8080", *force); err != nil {
		return err
	}
	fmt.Printf("initialized ovara deployment in %s\n\n", dir)
	// The token itself is not printed: terminal scrollback and CI logs keep
	// what is printed. The ovara commands that need it read it from there.
	fmt.Printf("operator token (gateway-root — keep it scarce): stored in %s (operator_tokens), readable only by you\n\n", filepath.Join(dir, "config.json"))
	fmt.Println("What you got: a policy (policy.json) where reading is free, changes need")
	fmt.Println("your approval, and known data-dump sites are blocked. Edit it any time.")
	fmt.Println()
	fmt.Println("next steps:")
	fmt.Println("  1. give Ovara the real API keys (the agent never sees them):")
	fmt.Println("       export GITHUB_TOKEN=... ANTHROPIC_API_KEY=... OPENAI_API_KEY=...")
	fmt.Println("  2. start it:")
	fmt.Printf("       ovara run -dir %s\n", dir)
	fmt.Println("  3. answer what the agent asks to do: open the approval-page link `ovara run`")
	fmt.Println("     prints, or in a second terminal:")
	fmt.Printf("       ovara watch -dir %s\n", dir)
	fmt.Println("  4. start your agent in a shell set up to go through Ovara:")
	fmt.Printf("       eval \"$(ovara env -dir %s)\"                 # bash / zsh\n", dir)
	fmt.Printf("       ovara env -dir %s -shell powershell | iex    # PowerShell\n", dir)
	fmt.Println()
	fmt.Println("not sure what this does? run:  ovara demo")
	return nil
}

// deploy writes a complete working deployment into dir. Returns the
// generated operator token.
func deploy(dir, gatewayPort string, force bool) (string, error) {
	randHex := func(n int) string {
		b := make([]byte, n)
		rand.Read(b)
		return hex.EncodeToString(b)
	}

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	receiptPub, receiptPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	_, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	// Two separate principals: the operator token is gateway-root
	// (approval resolution, policy, admin); the agent token is the proxy's
	// gateway_token and can only submit decisions + create/poll approvals.
	// The proxy can never approve its own escalations with it.
	operatorToken := randHex(32)
	agentToken := randHex(32)
	// Third principal: the credential the agent presents TO THE PROXY
	// (Proxy-Authorization). It buys proxy transit only — never gateway
	// access. Without it the credentialed proxy is an open dispenser.
	proxyToken := randHex(32)

	gwConfig := map[string]any{
		"server_port": gatewayPort,
		// Loopback-only: the approval/decision API must never be reachable
		// from a bounded agent, or the agent could approve its own
		// escalations. `ovara run` keeps gateway+proxy on the same host.
		"listen_addr":         "127.0.0.1",
		"policy_version":      "v1-local",
		"policy_file":         "policy.json",
		"log_level":           "info",
		"fail_closed":         true,
		"decision_log_file":   "var/log/decisions.jsonl",
		"receipt_signing_key": randHex(32),
		"auth_enabled":        true,
		"operator_tokens":     []string{operatorToken},
		"agent_tokens":        []string{agentToken},
		"trusted_issuers":     map[string]string{"ovara-init": hex.EncodeToString(issuerPub)},
		// Durable trust + signed journals out of the box (P2.4): a fresh
		// deployment must never run memory-mode authority stores — a
		// restart would otherwise silently lose identity, replay
		// protection, and every pending approval.
		"gateway_key_file":         "var/gateway.key",
		"gateway_registry_file":    "var/data/gateway_registry.jsonl",
		"identity_registry_file":   "var/data/identity_registry.json",
		"replay_file":              "var/data/replay.jsonl",
		"continuations_file":       "var/data/continuations.jsonl",
		"approvals_file":           "var/data/approvals.json",
		"execution_file":           "var/data/executions.jsonl",
		"receipts_file":            "var/data/receipts.json",
		"events_file":              "var/data/events.jsonl",
		"capabilities_file":        "var/data/capabilities.json",
		"enrollment_file":          "var/data/enrollment.json",
		"journal_signing_required": true,
	}

	policy := map[string]any{
		"version": "v2-init",
		// The most specific matching rule decides, so "allow exactly this
		// write, deny every other write" can be written. Files without
		// this field keep the older deny > allow > escalate order.
		"precedence": "most-specific",
		"rules":      defaultPolicyRules(),
	}

	proxyCfg := &config.Config{
		// Loopback only: an agent on this machine reaches it; the rest of
		// the network cannot. Use --boundary (or edit this) to expose it.
		ListenAddr:     "127.0.0.1:9443",
		GatewayURL:     "http://localhost:" + gatewayPort,
		GatewayToken:   agentToken,
		AgentToken:     proxyToken,
		Environment:    "dev",
		CACertFile:     "var/ca.pem",
		CAKeyFile:      "var/ca.key",
		ReceiptKeyFile: "var/receipt.key",
		ReceiptsFile:   "var/receipts.jsonl",
		PubKeyFile:     "var/receipt_pubkey.hex",
		Credentials: []creds.Binding{
			{Host: "api.github.com", Headers: map[string]string{"Authorization": "Bearer ${GITHUB_TOKEN}"}},
			{Host: "api.openai.com", Headers: map[string]string{"Authorization": "Bearer ${OPENAI_API_KEY}"}},
			{Host: "api.anthropic.com", Headers: map[string]string{"x-api-key": "${ANTHROPIC_API_KEY}", "anthropic-version": "2023-06-01"}},
			// The Slack Web API lives at slack.com/api/*; workspace hosts
			// (<team>.slack.com) are web pages and get no token.
			{Host: "slack.com", Headers: map[string]string{"Authorization": "Bearer ${SLACK_TOKEN}"}},
		},
	}

	type file struct {
		path string
		data []byte
		perm os.FileMode
	}
	mustJSON := func(v any) []byte {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			panic(err)
		}
		return append(b, '\n')
	}
	files := []file{
		{filepath.Join(dir, "var", "issuer.key"), []byte(hex.EncodeToString(issuerPriv) + "\n"), 0o600},
		{filepath.Join(dir, "var", "receipt.key"), []byte(hex.EncodeToString(receiptPriv) + "\n"), 0o600},
		{filepath.Join(dir, "var", "gateway.key"), []byte(hex.EncodeToString(gatewayPriv) + "\n"), 0o600},
		{filepath.Join(dir, "var", "receipt_pubkey.hex"), []byte(hex.EncodeToString(receiptPub) + "\n"), 0o644},
		{filepath.Join(dir, "config.json"), mustJSON(gwConfig), 0o600},
		// Owner-only: the agent's user must neither change the policy nor
		// read which hosts and commands get through.
		{filepath.Join(dir, "policy.json"), mustJSON(policy), 0o600},
		{filepath.Join(dir, "proxy.json"), mustJSON(proxyCfg), 0o600},
	}
	// The receipt signing key anchors every receipt ever written; init is
	// never a key-rotation path. Under -force we keep the existing key (and
	// its matching public half) instead of failing outright; without -force
	// any existing file is an error.
	if _, err := os.Stat(filepath.Join(dir, "var", "receipt.key")); err == nil {
		if !force {
			return "", fmt.Errorf("var/receipt.key already exists (use -force to re-init; the existing receipt key will be kept)")
		}
		fmt.Println("keeping existing receipt key (var/receipt.key)")
		kept := make([]file, 0, len(files))
		for _, f := range files {
			base := filepath.Base(f.path)
			if base == "receipt.key" || base == "receipt_pubkey.hex" {
				continue
			}
			kept = append(kept, f)
		}
		files = kept
	}
	// The gateway key is the journal-signing root: re-init must never
	// silently rotate it (existing signed journals would fail closed at
	// next boot). Same keep-on-force semantics as receipt.key.
	if _, err := os.Stat(filepath.Join(dir, "var", "gateway.key")); err == nil {
		fmt.Println("keeping existing gateway key (var/gateway.key)")
		kept := make([]file, 0, len(files))
		for _, f := range files {
			if filepath.Base(f.path) == "gateway.key" {
				continue
			}
			kept = append(kept, f)
		}
		files = kept
	}
	if !force {
		for _, f := range files {
			if _, err := os.Stat(f.path); err == nil {
				return "", fmt.Errorf("%s already exists (use -force to overwrite)", f.path)
			}
		}
	}
	for _, f := range files {
		// 0700: var/ holds keys, receipts, journals and logs.
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(f.path, f.data, f.perm); err != nil {
			return "", err
		}
	}
	return operatorToken, nil
}

// --- shared startup --------------------------------------------------------

// wire builds the executor proxy exactly as ovara-proxy does.
func wire(cfg *config.Config) (*proxy.Server, *ca.CA, error) {
	rootCA, err := ca.LoadOrCreate(cfg.CACertFile, cfg.CAKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: %w", err)
	}
	chain, err := receipts.LoadOrCreate(cfg.ReceiptsFile, cfg.ReceiptKeyFile, cfg.PubKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("receipts: %w", err)
	}
	anchorFile := os.Getenv("OVARA_ANCHOR_FILE")
	if anchorFile == "" {
		anchorFile = "var/anchors.jsonl"
	}
	if err := receipts.CheckBeforeResume(cfg.ReceiptsFile, anchorFile, cfg.PubKeyFile); err != nil {
		return nil, nil, err
	}
	anchorEvery, _ := strconv.Atoi(os.Getenv("OVARA_ANCHOR_EVERY"))
	chain.SetAnchoring(anchorFile, os.Getenv("OVARA_ANCHOR_URL"), anchorEvery)
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	bindings, skipped, err := creds.LoadReport(cfg.Credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("credentials: %w", err)
	}
	if cfg.ScopeRepo != "" {
		owner, repo, ok := strings.Cut(cfg.ScopeRepo, "/")
		if !ok || !creds.RepoName(owner) || !creds.RepoName(repo) {
			return nil, nil, fmt.Errorf("-scope-repo %q: want owner/repo", cfg.ScopeRepo)
		}
		for _, h := range []string{"api.github.com", "github.com"} {
			bindings = creds.ScopeToRepo(bindings, h, owner, repo)
		}
		log.Printf("GitHub credentials are limited to %s/%s for this run", owner, repo)
	}
	logSkippedBindings(skipped)
	// Tell `ovara env` which keys are really injected (names only).
	if err := writeActiveKeys(".", cfg.Credentials, skipped); err != nil {
		log.Printf("could not record active keys for `ovara env`: %v", err)
	}
	srv := proxy.New(rootCA, gw, bindings, chain, cfg.FailOpen)
	srv.SetEscalateWindow(time.Duration(cfg.EscalateTimeoutSec)*time.Second, time.Duration(cfg.EscalatePollSec)*time.Second)
	if cfg.GitGate != nil {
		srv.SetGitGate(*cfg.GitGate)
	}
	srv.SetSensitiveHosts(cfg.SensitiveHosts)
	srv.SetModelGate(cfg.ModelGate == nil || *cfg.ModelGate, cfg.ModelHosts)
	srv.ApplyConfig(cfg)
	srv.SetClientAuth(cfg.AgentToken)
	return srv, rootCA, nil
}

// logSkippedBindings tells the operator which hosts get no injected key
// because the key is not in Ovara's environment.
func logSkippedBindings(skipped []creds.Skipped) {
	for _, s := range skipped {
		log.Printf("no key injected for %s: %s not set in Ovara's environment (requests there go out with whatever the agent sends)",
			s.Host, strings.Join(s.Missing, ", "))
	}
}

// waitForGateway polls /health until it answers or the window closes.
func waitForGateway(base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	hc := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		resp, err := hc.Get(strings.TrimRight(base, "/") + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("gateway at %s did not become healthy within %s", base, timeout)
}

// --- run -------------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory from ovara init")
	boundary := fs.String("boundary", "", "set up an egress boundary before starting: netns or docker (requires root)")
	boundaryName := fs.String("boundary-name", "", "netns name or docker network name (defaults: agent0 / ovara-egress)")
	uiAddr := fs.String("ui", "127.0.0.1:9090", "address of the local approval page (loopback only; \"off\" to disable)")
	noUI := fs.Bool("no-ui", false, "run without the approval page (same as -ui off); without it, a page address that cannot be used stops ovara run")
	packageGate := fs.String("package-gate", "", "strict installs: a file of pinned packages (one ecosystem:name@version per line); a download of any other package asks policy (action_type package.install). `ovara box -profile strict` writes it from the project's lockfiles")
	allowUnhardened := fs.Bool("allow-unhardened-boundary", false, "with --boundary: go on when the host side of the boundary cannot be firewalled (neither iptables nor nft on the host); the agent can then reach every service on the host's boundary address")
	scopeRepo := fs.String("scope-repo", "", "limit the GitHub credentials to one repository (owner/repo) for this run: requests about any other repository go out without the key. `ovara box` sets it for the project it boxes")
	repairRegistry := fs.Bool("repair-registry", false, "once, for a deployment an older build left unable to restart (\"same file_seq with different hash\"): accept its identity registry if this gateway signed it, and seal it again")
	fs.Parse(args)
	server.RepairIdentityRegistry = *repairRegistry
	if *packageGate != "" { // read after the chdir below: make it absolute now
		if abs, err := filepath.Abs(*packageGate); err == nil {
			*packageGate = abs
		}
	}
	if err := os.Chdir(*dir); err != nil {
		return err
	}
	cfg, err := config.Load("proxy.json")
	if err != nil {
		return fmt.Errorf("proxy.json: %w (run `ovara init` first)", err)
	}
	// Hosts trusted for reads from an approval prompt are trusted for one
	// run: drop what a run that did not stop cleanly left behind, and what
	// this run adds when it stops.
	if hosts, err := dropRunTrust("."); err == nil && len(hosts) > 0 {
		log.Printf("reads from %s are no longer trusted (trusted from an approval prompt in an earlier run)", strings.Join(hosts, ", "))
	}
	defer func() {
		if hosts, err := dropRunTrust("."); err == nil && len(hosts) > 0 {
			log.Printf("reads from %s are no longer trusted (trusted from an approval prompt in this run)", strings.Join(hosts, ", "))
		}
	}()
	// The approval page's address is taken before anything else starts: if
	// it cannot be had, ovara run stops here instead of leaving the link a
	// person opens pointing at whatever holds the port.
	uiURL, err := openUI(*uiAddr, *noUI, cfg)
	if err != nil {
		return err
	}
	boundaryIP := ""
	if *boundary != "" {
		if boundaryIP, err = setupBoundary(*boundary, *boundaryName, cfg, *allowUnhardened); err != nil {
			return fmt.Errorf("boundary setup: %w", err)
		}
	}
	// The gateway owns SIGINT/SIGTERM: on a signal it closes its stores and
	// Run returns nil. The proxy must not outlive it (every check would fail
	// and the process would ignore the signal), so that also stops the proxy.
	gatewayDone := make(chan struct{})
	go func() {
		if err := server.Run("config.json"); err != nil {
			log.Fatalf("gateway: %v", err)
		}
		close(gatewayDone)
	}()
	if err := waitForGateway(cfg.GatewayURL, 10*time.Second); err != nil {
		return err
	}
	log.Printf("gateway healthy at %s", cfg.GatewayURL)
	cfg.ScopeRepo = *scopeRepo
	srv, _, err := wire(cfg)
	if err != nil {
		return err
	}
	if *packageGate != "" {
		b, err := os.ReadFile(*packageGate)
		if err != nil {
			return fmt.Errorf("-package-gate: %w", err)
		}
		pinned := lockfiles.ParsePins(string(b))
		srv.SetPackageGatePins(pinned)
		log.Printf("strict installs: %d pinned package(s) go through, checked against their lockfile digests where recorded; any other package download, or a registry download that names no package, asks policy (package.install)", len(pinned))
	}
	log.Printf("ovara executor proxy on %s (env=%s fail_open=%v)", cfg.ListenAddr, cfg.Environment, cfg.FailOpen)
	log.Printf("CA cert: %s — install into agent trust store", cfg.CACertFile)
	log.Printf("receipt chain: %s (pubkey: %s)", cfg.ReceiptsFile, cfg.PubKeyFile)
	if uiURL != "" {
		log.Printf("approve in your browser: %s", uiURL)
	}
	log.Printf("risky requests pause until you answer them (browser page above, or `ovara watch`)")
	listenAddr := cfg.ListenAddr
	addrs := proxyListenAddrs(listenAddr, boundaryIP)
	if len(addrs) > 1 {
		log.Printf("--boundary %s: listening on %s too, the host's side of the boundary, so the isolated agent can reach the proxy", *boundary, addrs[1])
	} else if host, _, err := net.SplitHostPort(listenAddr); err == nil && !isLoopbackHost(host) {
		log.Printf("WARNING: proxy listens on %s, reachable from the network. Anyone holding the proxy token can use it; set listen_addr to 127.0.0.1:PORT unless you meant this", listenAddr)
	}
	lns := make([]net.Listener, 0, len(addrs))
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return fmt.Errorf("proxy: %w", err)
		}
		lns = append(lns, ln)
	}
	hs := proxy.NewHTTPServer(listenAddr, srv)
	go func() {
		<-gatewayDone
		log.Printf("gateway stopped; stopping the proxy")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if hs.Shutdown(ctx) != nil {
			hs.Close() // paused requests waiting on a human: drop them
		}
	}()
	for _, ln := range lns[1:] {
		go func(ln net.Listener) {
			if err := hs.Serve(ln); err != http.ErrServerClosed {
				log.Printf("proxy on %s: %v", ln.Addr(), err)
			}
		}(ln)
	}
	if err := hs.Serve(lns[0]); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// openUI starts the approval page unless it is turned off (-no-ui or -ui
// off). An address that cannot be used is an error, not a warning: another
// local user holding the port (the agent's, say) would otherwise serve the
// page a person opens from an old link or a bookmark.
func openUI(addr string, off bool, cfg *config.Config) (string, error) {
	if off {
		return "", nil
	}
	url, err := startUI(addr, cfg)
	if err != nil {
		return "", fmt.Errorf("approval page on %s: %w (if another program holds that port, stop it, choose another with -ui 127.0.0.1:PORT, or run without the page with -no-ui)", addr, err)
	}
	return url, nil
}

// startUI serves the local approval page and returns the link to open
// (with a per-run page token in the fragment, never the operator token),
// or "" when disabled.
func startUI(addr string, cfg *config.Config) (string, error) {
	if addr == "" || addr == "off" {
		return "", nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("-ui %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("-ui must be a loopback address (127.0.0.1:PORT), got %q", addr)
	}
	admin, err := newAdminClient(".")
	if err != nil {
		return "", err
	}
	pageToken, err := newPageToken()
	if err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	ui := &uiServer{admin: admin, pageToken: pageToken, receiptsFile: cfg.ReceiptsFile, pubFile: cfg.PubKeyFile}
	go http.Serve(ln, ui.handler())
	return "http://" + ln.Addr().String() + "/#t=" + pageToken, nil
}

// setupBoundary runs the embedded egress-boundary script so the agent
// environment has no path around the proxy, and returns the host's address
// on the boundary (where the proxy must listen for the agent). Requires
// root (or passwordless sudo); the script is idempotent-ish and safe to
// re-run. It fails when the host side cannot be firewalled, unless
// allowUnhardened.
func setupBoundary(mode, name string, cfg *config.Config, allowUnhardened bool) (string, error) {
	if mode != "netns" && mode != "docker" {
		return "", fmt.Errorf("--boundary must be netns or docker, got %q", mode)
	}
	f, err := os.CreateTemp("", "ovara-boundary-*.sh")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(scripts.EgressBoundary); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		return "", err
	}

	_, proxyPort, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("proxy listen_addr %q: %w", cfg.ListenAddr, err)
	}
	args := []string{f.Name(), mode, "--proxy-port", proxyPort}
	ns := name
	if ns == "" {
		ns = "agent0"
	}
	subnetIdx := boundarySubnetIdx(ns)
	if mode == "netns" {
		// Chosen here (not left to the script's own hash) so the command we
		// print below names the address the script really configures.
		args = append(args, "--subnet-idx", strconv.Itoa(subnetIdx))
	}
	if name != "" {
		if mode == "netns" {
			args = append(args, "--name", name)
		} else {
			args = append(args, "--net", name)
		}
	}
	// the script's switches: DNS from the boundary is off unless the
	// operator turns it on (OVARA_BOUNDARY_DNS=1, with a deny-by-default
	// resolver); an unfirewalled host side is an error unless allowed
	var scriptEnv []string
	if v := os.Getenv("OVARA_BOUNDARY_DNS"); v != "" {
		scriptEnv = append(scriptEnv, "OVARA_BOUNDARY_DNS="+v)
	}
	if allowUnhardened {
		scriptEnv = append(scriptEnv, "OVARA_ALLOW_UNHARDENED=1")
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command("bash", args...)
	} else {
		// sudo strips the environment — pass the token via sudo's VAR=val
		// command form (transiently in argv; the token only buys proxy
		// transit, not a privilege). `sudo -E` is the alternative but is
		// denied on strict sudoers policies.
		sudoArgs := append(append([]string(nil), scriptEnv...), "bash")
		if cfg.AgentToken != "" {
			sudoArgs = append([]string{"OVARA_AGENT_TOKEN=" + cfg.AgentToken}, sudoArgs...)
		}
		cmd = exec.Command("sudo", append(sudoArgs, args...)...)
	}
	if os.Geteuid() == 0 {
		cmd.Env = append(os.Environ(), scriptEnv...)
		if cfg.AgentToken != "" {
			cmd.Env = append(cmd.Env, "OVARA_AGENT_TOKEN="+cfg.AgentToken)
		}
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	log.Printf("setting up %s egress boundary (requires root)...", mode)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == boundaryExitUnhardened {
			return "", errors.New("the host side of the boundary could not be firewalled (no iptables or nft on the host): the agent could reach every service on the host's boundary address. Install iptables or nftables, or pass -allow-unhardened-boundary to go on without it")
		}
		return "", err
	}
	if mode == "netns" {
		userinfo := ""
		if cfg.AgentToken != "" {
			userinfo = "agent:" + cfg.AgentToken + "@"
		}
		log.Printf("boundary up — run your agent inside it as an UNPRIVILEGED user that is NOT the user running Ovara")
		log.Printf("(root in the boundary could remove the firewall; the same user as Ovara could read its keys and edit policy.json):")
		log.Printf("  sudo useradd --system --no-create-home ovara-agent   # once")
		log.Printf("  sudo install -m 644 %s/var/ca.pem /usr/local/share/ovara-ca.pem   # the PUBLIC cert; the agent needs only this", mustGetwd())
		log.Printf("  sudo ip netns exec %s sudo -u ovara-agent env HTTPS_PROXY=http://%s%s:%s SSL_CERT_FILE=/usr/local/share/ovara-ca.pem <agent>", ns, userinfo, boundaryProxyIP(subnetIdx), proxyPort)
		log.Printf("and keep that user out of this directory:  chmod 700 %s", mustGetwd())
		return boundaryProxyIP(subnetIdx), nil
	}
	log.Printf("boundary network ready — launch the agent per the docker recipe above")
	return boundaryDockerIP, nil
}

// proxyListenAddrs is where the proxy listens: listen_addr, and with a
// boundary (boundaryIP set) and a loopback listen_addr, also the host's
// address on the boundary link, on the same port. The agent sits in a
// separate namespace or network and cannot reach the host's loopback; the
// boundary address is the only other place the proxy is offered, never
// every interface.
func proxyListenAddrs(listenAddr, boundaryIP string) []string {
	addrs := []string{listenAddr}
	if boundaryIP == "" {
		return addrs
	}
	if host, port, err := net.SplitHostPort(listenAddr); err == nil && isLoopbackHost(host) {
		addrs = append(addrs, net.JoinHostPort(boundaryIP, port))
	}
	return addrs
}

// boundaryExitUnhardened is setup-egress-boundary.sh's exit status when
// it cannot firewall the host side.
const boundaryExitUnhardened = 3

// boundaryDockerIP is the host's address on the docker boundary network
// (the bridge gateway of the script's 172.30.0.0/24).
const boundaryDockerIP = "172.30.0.1"

// boundarySubnetIdx maps a namespace name to a stable third octet (1..250)
// for the 10.200.N.0/24 boundary subnet, so two boundaries never collide.
func boundarySubnetIdx(name string) int {
	return int(crc32.ChecksumIEEE([]byte(name)))%250 + 1
}

// boundaryProxyIP is the host-side address the agent namespace reaches the
// proxy on (the script puts the host at .1 of the subnet).
func boundaryProxyIP(idx int) string { return "10.200." + strconv.Itoa(idx) + ".1" }

func mustGetwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "."
	}
	return d
}

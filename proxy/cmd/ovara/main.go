// Ovara is the unified CLI for a local deployment: one binary that
// generates a working gateway+proxy configuration (init), runs both
// halves (run), and proves the loop end-to-end (demo).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"hash/crc32"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"ovara.proxy/internal/proxy"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/scripts"
	"ovara.runtime.gateway/pkg/server"
)

// version is stamped by release builds: -ldflags "-X main.version=v0.10.0".
var version = "dev"

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
	case "run":
		err = cmdRun(os.Args[2:])
	case "demo":
		err = cmdDemo()
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "log":
		err = cmdLog(os.Args[2:])
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
  demo                  self-contained end-to-end demo (no network, no root)
  env [-dir .]          print the environment to run your agent through Ovara
  policy [-dir .]       explain the rules in plain English
  policy test "<METHOD URL>"  what would happen if the agent did this (dry run)
  watch [-dir .]        answer approval requests live: approve / deny each one
  approvals [-dir .]    list agent requests waiting for approval
  log [-dir .] [-n 50]  what the agent did (allowed/approved/blocked), integrity-checked
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
	token, err := deploy(dir, "8080", *force)
	if err != nil {
		return err
	}
	fmt.Printf("initialized ovara deployment in %s\n\n", dir)
	fmt.Printf("operator token (gateway-root — keep it scarce; also in config.json):\n  %s\n\n", token)
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
		"server_port":         gatewayPort,
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
		"gateway_key_file":        "var/gateway.key",
		"gateway_registry_file":   "var/data/gateway_registry.jsonl",
		"identity_registry_file":  "var/data/identity_registry.json",
		"replay_file":             "var/data/replay.jsonl",
		"continuations_file":      "var/data/continuations.jsonl",
		"approvals_file":          "var/data/approvals.json",
		"execution_file":          "var/data/executions.jsonl",
		"receipts_file":           "var/data/receipts.json",
		"events_file":             "var/data/events.jsonl",
		"capabilities_file":       "var/data/capabilities.json",
		"enrollment_file":         "var/data/enrollment.json",
		"journal_signing_required": true,
	}

	policy := map[string]any{
		"version": "v1-init",
		"rules":   defaultPolicyRules(),
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
			{Host: "*.slack.com", Headers: map[string]string{"Authorization": "Bearer ${SLACK_TOKEN}"}},
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
		{filepath.Join(dir, "policy.json"), mustJSON(policy), 0o644},
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
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
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
	anchorEvery, _ := strconv.Atoi(os.Getenv("OVARA_ANCHOR_EVERY"))
	chain.SetAnchoring(anchorFile, os.Getenv("OVARA_ANCHOR_URL"), anchorEvery)
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	bindings, skipped := creds.LoadReport(cfg.Credentials)
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
	fs.Parse(args)
	if err := os.Chdir(*dir); err != nil {
		return err
	}
	cfg, err := config.Load("proxy.json")
	if err != nil {
		return fmt.Errorf("proxy.json: %w (run `ovara init` first)", err)
	}
	if *boundary != "" {
		if err := setupBoundary(*boundary, *boundaryName, cfg); err != nil {
			return fmt.Errorf("boundary setup: %w", err)
		}
	}
	go func() {
		if err := server.Run("config.json"); err != nil {
			log.Fatalf("gateway: %v", err)
		}
	}()
	if err := waitForGateway(cfg.GatewayURL, 10*time.Second); err != nil {
		return err
	}
	log.Printf("gateway healthy at %s", cfg.GatewayURL)
	srv, _, err := wire(cfg)
	if err != nil {
		return err
	}
	log.Printf("ovara executor proxy on %s (env=%s fail_open=%v)", cfg.ListenAddr, cfg.Environment, cfg.FailOpen)
	log.Printf("CA cert: %s — install into agent trust store", cfg.CACertFile)
	log.Printf("receipt chain: %s (pubkey: %s)", cfg.ReceiptsFile, cfg.PubKeyFile)
	if url, err := startUI(*uiAddr, cfg); err != nil {
		log.Printf("approval page not started: %v", err)
	} else if url != "" {
		log.Printf("approve in your browser: %s", url)
	}
	log.Printf("risky requests pause until you answer them (browser page above, or `ovara watch`)")
	listenAddr := cfg.ListenAddr
	if *boundary != "" {
		// The agent sits in a separate namespace/network and reaches the
		// proxy over the boundary link, not over loopback.
		if host, port, err := net.SplitHostPort(listenAddr); err == nil && isLoopbackHost(host) {
			listenAddr = net.JoinHostPort("0.0.0.0", port)
			log.Printf("--boundary %s: listening on %s so the isolated agent can reach the proxy", *boundary, listenAddr)
		}
	} else if host, _, err := net.SplitHostPort(listenAddr); err == nil && !isLoopbackHost(host) {
		log.Printf("WARNING: proxy listens on %s, reachable from the network. Anyone holding the proxy token can use it; set listen_addr to 127.0.0.1:PORT unless you meant this", listenAddr)
	}
	return proxy.NewHTTPServer(listenAddr, srv).ListenAndServe()
}

// startUI serves the local approval page and returns the link to open
// (with the operator token in the fragment), or "" when disabled.
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
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	ui := &uiServer{admin: admin, receiptsFile: cfg.ReceiptsFile, pubFile: cfg.PubKeyFile}
	go http.Serve(ln, ui.handler())
	return "http://" + ln.Addr().String() + "/#t=" + admin.token, nil
}

// setupBoundary runs the embedded egress-boundary script so the agent
// environment has no path around the proxy. Requires root (or passwordless
// sudo); the script is idempotent-ish and safe to re-run.
func setupBoundary(mode, name string, cfg *config.Config) error {
	if mode != "netns" && mode != "docker" {
		return fmt.Errorf("--boundary must be netns or docker, got %q", mode)
	}
	f, err := os.CreateTemp("", "ovara-boundary-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(scripts.EgressBoundary); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		return err
	}

	_, proxyPort, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy listen_addr %q: %w", cfg.ListenAddr, err)
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
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command("bash", args...)
	} else {
		// sudo strips the environment — pass the token via sudo's VAR=val
		// command form (transiently in argv; the token only buys proxy
		// transit, not a privilege). `sudo -E` is the alternative but is
		// denied on strict sudoers policies.
		sudoArgs := []string{"bash"}
		if cfg.AgentToken != "" {
			sudoArgs = append([]string{"OVARA_AGENT_TOKEN=" + cfg.AgentToken}, sudoArgs...)
		}
		cmd = exec.Command("sudo", append(sudoArgs, args...)...)
	}
	if os.Geteuid() == 0 && cfg.AgentToken != "" {
		cmd.Env = append(os.Environ(), "OVARA_AGENT_TOKEN="+cfg.AgentToken)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	log.Printf("setting up %s egress boundary (requires root)...", mode)
	if err := cmd.Run(); err != nil {
		return err
	}
	if mode == "netns" {
		userinfo := ""
		if cfg.AgentToken != "" {
			userinfo = "agent:" + cfg.AgentToken + "@"
		}
		log.Printf("boundary up — run your agent inside it, as YOUR user (root in the boundary could remove the firewall):")
		log.Printf("  sudo ip netns exec %s sudo -u \"$USER\" env HTTPS_PROXY=http://%s%s:%s SSL_CERT_FILE=%s/var/ca.pem <agent>", ns, userinfo, boundaryProxyIP(subnetIdx), proxyPort, mustGetwd())
	} else {
		log.Printf("boundary network ready — launch the agent per the docker recipe above")
	}
	return nil
}

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

// --- demo ------------------------------------------------------------------

func cmdDemo() error {
	// The gateway and proxy log through the std logger; the demo narrates
	// instead, so silence it (set OVARA_DEMO_VERBOSE=1 to see everything).
	if os.Getenv("OVARA_DEMO_VERBOSE") == "" {
		log.SetOutput(io.Discard)
	}
	dir, err := os.MkdirTemp("", "ovara-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// Free port for the gateway.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	gwPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	if _, err := deploy(dir, gwPort, true); err != nil {
		return err
	}
	// Demo-only extra rule so we can show a block without touching the
	// network: anything with "leak" in the URL is denied. The real default
	// policy blocks known data-dump sites instead.
	// (Applied below, once the demo upstream's address is known.)
	if err := os.Chdir(dir); err != nil {
		return err
	}
	cfg, err := config.Load("proxy.json")
	if err != nil {
		return err
	}
	cfg.GatewayURL = "http://127.0.0.1:" + gwPort
	cfg.EscalatePollSec = 1

	// Local "upstream" the agent wants to reach.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"method":%q,"path":%q}`, r.Method, r.URL.Path)
	}))
	defer upstream.Close()
	if err := addDemoDenyRule(filepath.Join(dir, "policy.json"), upstream.Listener.Addr().String()); err != nil {
		return err
	}

	go func() {
		if err := server.Run("config.json"); err != nil {
			log.Printf("gateway: %v", err)
		}
	}()
	if err := waitForGateway(cfg.GatewayURL, 15*time.Second); err != nil {
		return err
	}

	srv, rootCA, err := wire(cfg)
	if err != nil {
		return err
	}
	// The demo upstream is loopback — the SSRF destination guard would
	// correctly refuse it, so it is disabled for the demo only.
	srv.SetPublicEgressOnly(false)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go http.Serve(proxyLn, srv)
	proxyURL, _ := url.Parse("http://" + proxyLn.Addr().String())
	if cfg.AgentToken != "" {
		proxyURL.User = url.UserPassword("agent", cfg.AgentToken)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootCA.CertPEM())
	agent := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	admin, err := newAdminClient(".")
	if err != nil {
		return err
	}

	say := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	say("")
	say("Ovara demo — an AI agent, a checkpoint it cannot bypass, and you.")
	say("Everything below is local: no network, no real credentials.")
	say("")
	say("The agent's only way out is through Ovara. Ovara checks every request")
	say("against policy.json: reading is free, changing things needs a human,")
	say("and known data-dump sites are blocked.")

	// 1 — a read.
	say("\n━━ 1. The agent reads something")
	say("   agent → GET %s/v1/models", upstream.URL)
	code, _ := agentCall(agent, "GET", upstream.URL+"/v1/models")
	say("   ✓ ALLOWED (HTTP %d) — policy: \"reading is allowed\"", code)

	// 2 — a write: pauses for a human.
	say("\n━━ 2. The agent tries to change something (think: git push, merge a PR, deploy)")
	say("   agent → POST %s/v1/deploy", upstream.URL)
	say("   ⏸  PAUSED — Ovara is holding the request until a human decides")
	humanDone := make(chan struct{})
	go func() {
		defer close(humanDone)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			list, err := admin.pending()
			if err == nil && len(list) > 0 {
				a := list[0]
				say("   📩 you would see this (in `ovara watch`): the agent wants to: %s", describe(a.Resource))
				time.Sleep(1500 * time.Millisecond)
				if err := admin.resolve(a.ApprovalID, true, "demo-human", ""); err != nil {
					say("   (demo could not approve: %v)", err)
				} else {
					say("   👍 you approve it")
				}
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	code, _ = agentCall(agent, "POST", upstream.URL+"/v1/deploy")
	<-humanDone
	if code != http.StatusOK {
		return fmt.Errorf("demo: approved request returned HTTP %d, want 200", code)
	}
	say("   ✓ went through after approval (HTTP %d)", code)

	// 3 — a leak attempt: blocked outright.
	say("\n━━ 3. The agent tries to send data somewhere it shouldn't")
	say("   agent → POST %s/leak/secrets", upstream.URL)
	code, _ = agentCall(agent, "POST", upstream.URL+"/leak/secrets")
	if code == http.StatusOK {
		return fmt.Errorf("demo: leak request was NOT blocked")
	}
	say("   ✗ BLOCKED (HTTP %d) — no human needed, policy says no", code)

	// 4 — evidence.
	say("\n━━ 4. Evidence: every decision left a signed receipt")
	pubBytes, err := hex.DecodeString(strings.TrimSpace(mustRead(cfg.PubKeyFile)))
	if err != nil {
		return err
	}
	printReceipts(cfg.ReceiptsFile)
	res := receipts.VerifyFile(cfg.ReceiptsFile, ed25519.PublicKey(pubBytes))
	if !res.Valid {
		return fmt.Errorf("receipt chain failed verification at %d: %s", res.FailAt, res.Reason)
	}
	say("   chain of %d receipts verified offline: valid ✓ (tampering with any one would break it)", res.Total)

	say("\nThat is the whole idea. To use it for real:")
	say("   ovara init mydir && ovara run -dir mydir     # start it")
	say("   ovara watch -dir mydir                       # answer approval requests")
	say("   ovara log -dir mydir                         # see what the agent did")
	say("")
	return nil
}

// agentCall makes one proxied request and returns the HTTP status.
func agentCall(c *http.Client, method, target string) (int, string) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return 0, err.Error()
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// addDemoDenyRule prepends a deny rule for URLs containing "leak".
func addDemoDenyRule(policyPath, upstreamAddr string) error {
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	var pol map[string]any
	if err := json.Unmarshal(raw, &pol); err != nil {
		return err
	}
	rules, _ := pol["rules"].([]any)
	deny := map[string]any{
		"action_type": "http.request", "environment": "*", "resource": "POST *leak*",
		"deny": true, "description": "Demo only: block anything that looks like leaking data",
	}
	// The demo's "read" goes to its own loopback upstream, which (rightly)
	// is not on the trusted-host list of the real default policy.
	read := map[string]any{
		"action_type": "http.request", "environment": "*", "resource": "GET http://" + upstreamAddr + "/*",
		"allow": true, "description": "Demo only: reading the demo upstream is allowed",
	}
	pol["rules"] = append([]any{deny, read}, rules...)
	out, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(policyPath, append(out, '\n'), 0o644)
}

// printReceipts lists one line per receipt in the chain.
func printReceipts(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r receipts.Receipt
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		fmt.Printf("   • %-5s %-7s %s\n", strings.ToUpper(r.Decision), r.Method, r.URL)
	}
}

func mustRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// printLastReceipt prints the most recent chain entry's decision fields.
func printLastReceipt(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var r receipts.Receipt
	if json.Unmarshal([]byte(lines[len(lines)-1]), &r) != nil {
		return
	}
	fmt.Printf("  receipt %s: %s %s → %s (%d)\n", r.ReceiptID, r.Method, r.URL, r.Decision, r.Status)
}

// defaultPolicyRules is what `ovara init` writes to policy.json. The idea,
// in one line: reading is free, writing needs a human, and a few known
// data-dump sites are blocked outright. The gateway decides deny > allow >
// escalate, so a more specific allow below also overrides the "writes
// need approval" rules. Edit policy.json freely; changes are picked up
// without a restart.
func defaultPolicyRules() []map[string]any {
	rule := func(resource, effect, desc string) map[string]any {
		r := map[string]any{"action_type": "http.request", "environment": "*", "description": desc}
		if resource != "" {
			r["resource"] = resource
		}
		r[effect] = true
		return r
	}
	rules := []map[string]any{}
	// Reading is free, but only from places an agent legitimately needs:
	// package registries, code hosts and documentation. A blanket "GET *"
	// would let an agent send data to ANY server it controls (the path and
	// query of a GET carry data just as well as a POST body), so a host that
	// is not listed here pauses for approval like everything else.
	for _, h := range trustedReadHosts {
		rules = append(rules,
			rule("GET https://"+h+"/*", "allow", "Reading from "+h+" is allowed"),
			rule("HEAD https://"+h+"/*", "allow", "Reading from "+h+" is allowed"),
		)
	}
	// git clone/fetch/pull speak smart-HTTP with a POST to git-upload-pack;
	// it only reads. The host is part of the rule: a bare "*git-upload-pack"
	// would match a POST to ANY server whose path ends that way.
	for _, h := range trustedGitHosts {
		rules = append(rules, rule("POST https://"+h+"/*git-upload-pack", "allow", "git clone/fetch/pull from "+h+" is reading"))
	}
	rules = append(rules,
		// The agent must be able to talk to its own model provider.
		rule("POST https://api.anthropic.com/*", "allow", "The agent may call the Anthropic API"),
		rule("POST https://api.openai.com/*", "allow", "The agent may call the OpenAI API"),
		// Known places where stolen data typically gets dumped.
		rule("*://pastebin.com/*", "deny", "Blocked: paste site commonly used to leak data"),
		rule("*://transfer.sh/*", "deny", "Blocked: anonymous file drop"),
		rule("*://webhook.site/*", "deny", "Blocked: request-capture site commonly used to leak data"),
		rule("*://*.requestbin.com/*", "deny", "Blocked: request-capture site commonly used to leak data"),
		// Anything that changes something out in the world needs a human.
		// This covers git push, opening/merging PRs, deleting branches,
		// triggering deploys and posting messages.
		rule("POST *", "escalate", "Writes need approval (git push, PRs, deploys, messages)"),
		rule("PUT *", "escalate", "Writes need approval"),
		rule("PATCH *", "escalate", "Writes need approval"),
		rule("DELETE *", "escalate", "Deletes need approval"),
		// Anything we did not think of, including reads from a host that is
		// not on the trusted list: ask.
		rule("", "escalate", "Catch-all: anything unrecognised requires approval"),
	)
	return rules
}

// isLoopbackHost reports whether a listen host is loopback-only. An empty
// host (":9443") means every interface, so it is not.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// trustedGitHosts may be cloned/fetched from without approval.
var trustedGitHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

// trustedReadHosts may be read from without approval: package registries,
// code hosts, and documentation. Add your own hosts in policy.json.
var trustedReadHosts = []string{
	// code hosts
	"github.com", "api.github.com", "raw.githubusercontent.com",
	"codeload.github.com", "objects.githubusercontent.com", "gitlab.com", "bitbucket.org",
	// package registries
	"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
	"proxy.golang.org", "sum.golang.org", "index.crates.io", "static.crates.io", "crates.io",
	"rubygems.org", "repo.maven.apache.org", "repo1.maven.org", "pkg.go.dev",
	// documentation
	"docs.python.org", "go.dev", "developer.mozilla.org", "nodejs.org",
	"docs.anthropic.com", "platform.openai.com", "docs.github.com",
}

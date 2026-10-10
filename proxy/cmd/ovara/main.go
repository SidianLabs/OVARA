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
	"ovara.proxy/internal/proxy"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/runallow"
	"ovara.proxy/scripts"
	"ovara.runtime.gateway/pkg/server"
)

// version is stamped by release builds: -ldflags "-X main.version=v0.10.0".
var version = devVersion

// devVersion is the version of a build that no release stamped.
const devVersion = "dev"

// boxImage is stamped by release builds: the box image this ovara was
// released with, by digest (ghcr.io/sidianlabs/ovara-box@sha256:...), so
// `ovara box -tier 2` pulls exactly that image. Development builds leave it
// empty and use a locally built "ovara-box".
var boxImage = ""

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
		if boxImage != "" {
			fmt.Println("box image", boxImage)
		}
		return
	case "init":
		err = cmdInit(os.Args[2:])
	case "box":
		err = cmdBox(os.Args[2:])
	case "box-init": // PID 1 of a tier 2 box; started by `ovara box -tier 2`, not by people
		err = cmdBoxInit(os.Args[2:])
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
	if err == nil {
		chain.SetRotation(cfg.ReceiptsSegmentBytes)
	}
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
	packageGate := fs.String("package-gate", "", "strict installs: a file of pinned packages (one ecosystem:name@version per line); a download of any other package asks policy (action_type package.install). `ovara box -profile strict` writes it from the project's lockfiles")
	unattended := fs.Bool("unattended", false, "no one will answer: refuse at once anything policy would pause (CI)")
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
	if *boundary != "" {
		if err := setupBoundary(*boundary, *boundaryName, cfg); err != nil {
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
	srv, _, err := wire(cfg)
	if err != nil {
		return err
	}
	// "approve for this run": a fresh, empty list each run
	if abs, err := filepath.Abs(runallow.File); err == nil {
		if err := runallow.Reset(abs, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			log.Printf("run allowances not available: %v", err)
		} else {
			srv.SetRunAllowances(abs)
		}
	}
	if *unattended {
		srv.SetUnattended(true)
		log.Printf("unattended: anything policy would pause is refused at once")
	}
	if *packageGate != "" {
		b, err := os.ReadFile(*packageGate)
		if err != nil {
			return fmt.Errorf("-package-gate: %w", err)
		}
		pinned := strings.Fields(string(b))
		srv.SetPackageGate(pinned)
		log.Printf("strict installs: %d pinned package(s) go through; any other package download asks policy (package.install)", len(pinned))
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
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
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
		log.Printf("boundary up — run your agent inside it as an UNPRIVILEGED user that is NOT the user running Ovara")
		log.Printf("(root in the boundary could remove the firewall; the same user as Ovara could read its keys and edit policy.json):")
		log.Printf("  sudo useradd --system --no-create-home ovara-agent   # once")
		log.Printf("  sudo install -m 644 %s/var/ca.pem /usr/local/share/ovara-ca.pem   # the PUBLIC cert; the agent needs only this", mustGetwd())
		log.Printf("  sudo ip netns exec %s sudo -u ovara-agent env HTTPS_PROXY=http://%s%s:%s SSL_CERT_FILE=/usr/local/share/ovara-ca.pem <agent>", ns, userinfo, boundaryProxyIP(subnetIdx), proxyPort)
		log.Printf("and keep that user out of this directory:  chmod 700 %s", mustGetwd())
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

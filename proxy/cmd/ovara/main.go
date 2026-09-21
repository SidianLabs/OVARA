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

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "demo":
		err = cmdDemo()
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

  init [dir] [-force]   generate a working gateway+proxy deployment
  run [-dir .]          start the gateway and the executor proxy
  demo                  self-contained end-to-end demo (no network, no root)`)
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
	fmt.Println("next steps:")
	fmt.Println("  1. export secrets for the credential bindings, e.g.:")
	fmt.Println("       export GITHUB_TOKEN=... OPENAI_API_KEY=... ANTHROPIC_API_KEY=... SLACK_TOKEN=...")
	fmt.Println("  2. run it:")
	fmt.Printf("       ovara run -dir %s\n", dir)
	fmt.Println("  3. point your agent at the proxy and trust var/ca.pem")
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
	}

	policy := map[string]any{
		"version": "v1-init",
		"rules": []map[string]any{
			{"action_type": "http.request", "environment": "dev", "allow": true,
				"description": "Dev HTTP egress is allowed — the proxy still receipts every transit"},
			{"action_type": "*", "environment": "*", "escalate": true,
				"description": "Catch-all: anything else requires approval"},
		},
	}

	proxyCfg := &config.Config{
		ListenAddr:     ":9443",
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
	srv := proxy.New(rootCA, gw, creds.Load(cfg.Credentials), chain, cfg.FailOpen)
	srv.SetEscalateWindow(time.Duration(cfg.EscalateTimeoutSec)*time.Second, time.Duration(cfg.EscalatePollSec)*time.Second)
	if cfg.GitGate != nil {
		srv.SetGitGate(*cfg.GitGate)
	}
	srv.SetSensitiveHosts(cfg.SensitiveHosts)
	srv.SetClientAuth(cfg.AgentToken)
	return srv, rootCA, nil
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
	return http.ListenAndServe(cfg.ListenAddr, srv)
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
	ns := name
	if ns == "" {
		ns = "agent0"
	}
	if mode == "netns" {
		userinfo := ""
		if cfg.AgentToken != "" {
			userinfo = "agent:" + cfg.AgentToken + "@"
		}
		log.Printf("boundary up — run your agent inside it:")
		log.Printf("  sudo ip netns exec %s env HTTPS_PROXY=http://%s10.200.0.1:%s SSL_CERT_FILE=%s/var/ca.pem <agent>", ns, userinfo, proxyPort, mustGetwd())
	} else {
		log.Printf("boundary network ready — launch the agent per the docker recipe above")
	}
	return nil
}

func mustGetwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "."
	}
	return d
}

// --- demo ------------------------------------------------------------------

func cmdDemo() error {
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
	if err := os.Chdir(dir); err != nil {
		return err
	}
	cfg, err := config.Load("proxy.json")
	if err != nil {
		return err
	}
	cfg.GatewayURL = "http://127.0.0.1:" + gwPort

	// Local "upstream" the agent wants to reach.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"path":%q,"via":"ovara demo upstream"}`, r.URL.Path)
	}))
	defer upstream.Close()

	go func() {
		if err := server.Run("config.json"); err != nil {
			log.Printf("gateway: %v", err)
		}
	}()
	if err := waitForGateway(cfg.GatewayURL, 10*time.Second); err != nil {
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
		// Client auth: the demo agent authenticates exactly like a real
		// one — credentials in the proxy URL.
		proxyURL.User = url.UserPassword("agent", cfg.AgentToken)
	}

	// Client trusts the generated CA (needed for CONNECT+MITM hosts) and
	// egresses only via the proxy.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootCA.CertPEM())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	target := upstream.URL + "/v1/models"
	fmt.Printf("→ agent request: GET %s (via proxy %s, plain-HTTP path)\n", target, proxyURL.Host)
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("proxied request: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("← upstream response: %s %s\n", resp.Status, strings.TrimSpace(string(body)))
	printLastReceipt(cfg.ReceiptsFile)

	// Deny path: a second proxy instance whose gateway is unreachable runs
	// fail-closed — the deny is receipted exactly like the allow.
	deadGW := gateway.New("http://127.0.0.1:1", cfg.GatewayToken, cfg.Environment)
	chain2, err := receipts.LoadOrCreate(cfg.ReceiptsFile, cfg.ReceiptKeyFile, cfg.PubKeyFile)
	if err != nil {
		return err
	}
	denySrv := proxy.New(rootCA, deadGW, nil, chain2, false)
	denyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go http.Serve(denyLn, denySrv)
	denyURL, _ := url.Parse("http://" + denyLn.Addr().String())
	denyClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(denyURL)}}

	fmt.Printf("\n→ agent request with gateway unreachable (fail-closed): GET %s\n", target)
	resp2, err := denyClient.Get(target)
	if err != nil {
		return fmt.Errorf("deny request: %w", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	fmt.Printf("← proxy decision: %s %s\n", resp2.Status, strings.TrimSpace(string(body2)))
	printLastReceipt(cfg.ReceiptsFile)

	// Verify the receipt chain offline.
	pubBytes, err := hex.DecodeString(strings.TrimSpace(mustRead(cfg.PubKeyFile)))
	if err != nil {
		return err
	}
	res := receipts.VerifyFile(cfg.ReceiptsFile, ed25519.PublicKey(pubBytes))
	fmt.Printf("\nreceipt chain: %d receipts, valid=%v\n", res.Total, res.Valid)
	if !res.Valid {
		return fmt.Errorf("chain verification failed at %d: %s", res.FailAt, res.Reason)
	}
	fmt.Println("✓ request executed through the chokepoint and receipted — chain valid")
	fmt.Println("  (this exercises the plain-HTTP proxy path; CONNECT+MITM is covered by internal/proxy tests)")
	return nil
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

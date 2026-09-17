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
	force := fs.Bool("force", false, "overwrite existing files")
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
	fmt.Printf("operator token (shown once, also in config.json / proxy.json):\n  %s\n\n", token)
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
	token := randHex(32)

	gwConfig := map[string]any{
		"server_port":         gatewayPort,
		"policy_version":      "v1-local",
		"policy_file":         "policy.json",
		"log_level":           "info",
		"fail_closed":         true,
		"decision_log_file":   "var/log/decisions.jsonl",
		"receipt_signing_key": randHex(32),
		"auth_enabled":        true,
		"operator_tokens":     []string{token},
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
		GatewayToken:   token,
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
	return token, nil
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
	fs.Parse(args)
	if err := os.Chdir(*dir); err != nil {
		return err
	}
	cfg, err := config.Load("proxy.json")
	if err != nil {
		return fmt.Errorf("proxy.json: %w (run `ovara init` first)", err)
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
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go http.Serve(proxyLn, srv)
	proxyURL, _ := url.Parse("http://" + proxyLn.Addr().String())

	// Client trusts the generated CA (needed for CONNECT+MITM hosts) and
	// egresses only via the proxy.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootCA.CertPEM())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	target := upstream.URL + "/v1/models"
	fmt.Printf("→ agent request: GET %s (via proxy %s)\n", target, proxyURL.Host)
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

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
	"ovara.runtime.gateway/pkg/server"
)

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

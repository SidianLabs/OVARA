package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/creds"
)

// fakeGitHubUpstream is one TLS server that answers both as api.github.com
// (the installation-token endpoint the broker calls) and as the upstream
// the agent talks to (127.0.0.1:port), which reflects the credential it
// received.
type fakeGitHubUpstream struct {
	srv      *httptest.Server
	mints    atomic.Int32
	upstream atomic.Int32
	fail     atomic.Bool
	mu       sync.Mutex
	sawAuth  string
}

func newFakeGitHubUpstream(t *testing.T) *fakeGitHubUpstream {
	t.Helper()
	g := &fakeGitHubUpstream{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "api.github.com" && r.URL.Path == "/app/installations/7/access_tokens" {
			n := g.mints.Add(1)
			if g.fail.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      fmt.Sprintf("ghs_brokered%04dQQQQQQQQQQQQQQQQ", n),
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			})
			return
		}
		g.upstream.Add(1)
		auth := r.Header.Get("Authorization")
		g.mu.Lock()
		g.sawAuth = auth
		g.mu.Unlock()
		tok := ""
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err == nil {
			_, tok, _ = strings.Cut(string(raw), ":")
		}
		// A reflector: echoes the header and the bare token, in headers
		// and body.
		w.Header().Set("X-Echo", auth)
		w.Header().Set("X-Echo-Token", tok)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "auth=%s token=%s b64=%s", auth, tok, base64.StdEncoding.EncodeToString([]byte(tok)))
	})
	g.srv = httptest.NewUnstartedServer(h)
	g.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{selfSignedFor(t, "api.github.com", "127.0.0.1")}}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHubUpstream) auth() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sawAuth
}

func selfSignedFor(t *testing.T, name, ip string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// brokerFixture is a proxy whose one binding, for the fake upstream,
// mints GitHub App tokens at "api.github.com" (the fake, reached through
// the proxy's own transport with verified TLS).
func brokerFixture(t *testing.T, g *fakeGitHubUpstream) *fixture {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	t.Setenv("TEST_BROKER_APP_ID", "999")
	bindings, skipped, err := creds.LoadReport([]creds.Binding{{
		Host:      mustHostPort(t, g.srv.URL),
		GitHubApp: &creds.GitHubApp{AppID: "${TEST_BROKER_APP_ID}", InstallationID: "7", PrivateKeyFile: keyFile},
	}})
	if err != nil || len(skipped) > 0 {
		t.Fatalf("load: %v %v", err, skipped)
	}
	f := newFixture(t, "allow", bindings)
	upAddr := g.srv.Listener.Addr().String()
	d := &net.Dialer{Timeout: 5 * time.Second}
	f.srv.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "api.github.com:") {
			addr = upAddr
		}
		return d.DialContext(ctx, network, addr)
	}
	return f
}

// syncBuffer collects log output from concurrent goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// A minted token goes upstream (here in the git smart-HTTP Basic form, as
// the host is not an "api." host), is scrubbed from a reflecting
// response like a static secret, and appears in no log line and no
// receipt. The broker's own call to the issuer is not a receipted,
// policy-checked request.
func TestBrokeredTokenInjectedAndScrubbed(t *testing.T) {
	logs := captureLog(t)
	g := newFakeGitHubUpstream(t)
	f := brokerFixture(t, g)
	resp, body := tunnelReq(t, f.srv, g.srv, f.ca, "GET", "/acme/app.git/info/refs", map[string]string{"Authorization": "Bearer agent-own-token"}) //nolint:bodyclose // the helper reads and closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	auth := g.auth()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if !strings.HasPrefix(auth, "Basic ") || err != nil || !strings.HasPrefix(string(raw), "x-access-token:ghs_brokered") {
		t.Fatalf("upstream saw Authorization %q, want Basic x-access-token:<minted>", auth)
	}
	tok := strings.TrimPrefix(string(raw), "x-access-token:")
	b64 := base64.StdEncoding.EncodeToString([]byte(tok))
	for _, leak := range []string{tok, auth, b64[:len(b64)-4]} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("minted credential reflected to the agent in the body: %s", body)
		}
		for k, vv := range resp.Header {
			for _, v := range vv {
				if strings.Contains(v, leak) {
					t.Fatalf("minted credential reflected in header %s: %s", k, v)
				}
			}
		}
	}
	if !strings.Contains(string(body), "[REDACTED]") {
		t.Fatalf("expected redaction markers in %s", body)
	}
	if g.mints.Load() != 1 || g.upstream.Load() != 1 {
		t.Fatalf("mints %d upstream %d", g.mints.Load(), g.upstream.Load())
	}
	// Second request reuses the token.
	tunnelReq(t, f.srv, g.srv, f.ca, "GET", "/acme/app.git/info/refs", nil) //nolint:bodyclose // the helper reads and closes the body
	if g.mints.Load() != 1 {
		t.Fatalf("token minted again for the second request (%d)", g.mints.Load())
	}
	if strings.Contains(logs.String(), tok) {
		t.Fatal("the minted token appears in the log")
	}
	if !strings.Contains(logs.String(), "minted a short-lived token") {
		t.Fatalf("mint not logged: %s", logs.String())
	}
	chain, _ := os.ReadFile(f.chainFile)
	if strings.Contains(string(chain), tok) || strings.Contains(string(chain), b64) {
		t.Fatal("the minted token appears in a receipt")
	}
	if strings.Contains(string(chain), "access_tokens") {
		t.Fatal("the broker's own call to the issuer was receipted as agent traffic")
	}
}

// When no token can be minted the request is refused with a clear error
// and is not forwarded, with or without the agent's own credential.
func TestBrokerFailureRequestNotForwarded(t *testing.T) {
	captureLog(t)
	g := newFakeGitHubUpstream(t)
	g.fail.Store(true)
	f := brokerFixture(t, g)
	resp, body := tunnelReq(t, f.srv, g.srv, f.ca, "GET", "/acme/app.git/info/refs", map[string]string{"Authorization": "Bearer agent-own-token"}) //nolint:bodyclose // the helper reads and closes the body
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(string(body), "credential_unavailable") || !strings.Contains(string(body), "not sent") {
		t.Fatalf("refusal does not say why: %s", body)
	}
	if n := g.upstream.Load(); n != 0 {
		t.Fatalf("request forwarded %d time(s) without a minted token", n)
	}
	if g.mints.Load() != 1 {
		t.Fatalf("mint attempts %d, want 1", g.mints.Load())
	}
	r := f.lastReceipt(t)
	if r.Decision != "error" || len(r.Reasons) == 0 || r.Reasons[len(r.Reasons)-1] != "credential_unavailable" {
		t.Fatalf("receipt %+v", r)
	}
}

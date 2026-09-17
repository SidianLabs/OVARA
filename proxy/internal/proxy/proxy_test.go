package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

type fixture struct {
	srv       *Server
	chainFile string
	pubFile   string
	ca        *ca.CA
}

func newFixture(t *testing.T, gwDecision string, bindings []creds.Binding) *fixture {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	chainFile := filepath.Join(dir, "receipts.jsonl")
	pubFile := filepath.Join(dir, "receipts.pub")
	chain, err := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "receipts.key"), pubFile)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"decision": gwDecision, "decision_id": "d-test"})
	}))
	t.Cleanup(gw.Close)
	return &fixture{
		srv:       New(c, gateway.New(gw.URL, "", "test"), bindings, chain, false),
		chainFile: chainFile,
		pubFile:   pubFile,
		ca:        c,
	}
}

func (f *fixture) lastReceipt(t *testing.T) receipts.Receipt {
	t.Helper()
	data, err := readLastLine(f.chainFile)
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	var r receipts.Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	return r
}

func readLastLine(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' && i < len(data)-1 {
			return data[i+1:], nil
		}
	}
	return data, nil
}

func TestPlainHTTPAllowInjectsCredsAndReceipts(t *testing.T) {
	var sawHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("Authorization")
		w.WriteHeader(201)
		fmt.Fprint(w, "upstream-body")
	}))
	defer upstream.Close()
	host := mustHost(t, upstream.URL)

	f := newFixture(t, "allow", []creds.Binding{
		{Host: host, Headers: map[string]string{"Authorization": "Bearer real"}},
	})

	req, _ := http.NewRequest("GET", upstream.URL+"/path", nil)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	if rec.Code != 201 || rec.Body.String() != "upstream-body" {
		t.Fatalf("bad proxied response: %d %q", rec.Code, rec.Body.String())
	}
	if sawHeader != "Bearer real" {
		t.Fatalf("credential not injected, upstream saw %q", sawHeader)
	}
	r := f.lastReceipt(t)
	if r.Decision != "allow" || r.Status != 201 || r.Method != "GET" {
		t.Fatalf("bad receipt: %+v", r)
	}
}

func TestPlainHTTPDeny(t *testing.T) {
	f := newFixture(t, "deny", nil)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:1/", nil)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	r := f.lastReceipt(t)
	if r.Decision != "deny" {
		t.Fatalf("expected deny receipt, got %+v", r)
	}
}

func TestPlainHTTPFailClosed(t *testing.T) {
	dir := t.TempDir()
	c, _ := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	chainFile := filepath.Join(dir, "r.jsonl")
	chain, _ := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	// gateway pointing at a dead address
	gw := gateway.New("http://127.0.0.1:1", "", "test")
	s := New(c, gw, nil, chain, false)

	req, _ := http.NewRequest("GET", "http://127.0.0.1:1/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed, got %d", rec.Code)
	}
}

// TestConnectMITM exercises the CONNECT tunnel: client TLS handshake against
// the CA-minted leaf, inner request dispatched through gateway+receipt path.
// Upstream is a TLS server the proxy's transport cannot trust, so a 502 is
// expected — it still proves the full MITM path executed.
func TestConnectMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()
	target := mustHostPort(t, upstream.URL)

	f := newFixture(t, "allow", nil)
	proxySrv := httptest.NewServer(f.srv)
	defer proxySrv.Close()

	proxyAddr := mustHostPort(t, proxySrv.URL)
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %d", resp.StatusCode)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.ca.CertPEM()) {
		t.Fatal("bad CA PEM")
	}
	host, _, _ := net.SplitHostPort(target)
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("MITM handshake failed (leaf not trusted): %v", err)
	}
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	tresp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	// upstream uses an untrusted test cert -> proxy returns 502
	if tresp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 from untrusted upstream, got %d", tresp.StatusCode)
	}
	tresp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		r := f.lastReceipt(t)
		if r.Method == "GET" && r.Decision != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no receipt written for tunneled request")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func mustHostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

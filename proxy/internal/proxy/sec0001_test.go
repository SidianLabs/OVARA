package proxy

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

const testSecret = "Bearer sk-live-SECRET-123"

// reflector echoes the Authorization header back in the body, the way
// httpbin /headers or a debug endpoint would. It honours gzip and Range
// like a real server.
func reflector() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "you sent: " + r.Header.Get("Authorization")
		if r.Header.Get("Range") != "" {
			w.Header().Set("Content-Range", "bytes 10-20/40")
			w.WriteHeader(http.StatusPartialContent)
			io.WriteString(w, body[10:20])
			return
		}
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			io.WriteString(gz, body)
			gz.Close()
			return
		}
		io.WriteString(w, body)
	}))
}

// tunnel sends one GET through the proxy's CONNECT+MITM path and returns
// the raw response the agent receives (no transparent decoding).
func tunnel(t *testing.T, srv *Server, c *ca.CA, upstream *httptest.Server, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	srv.transport.TLSClientConfig.RootCAs = pool
	proxySrv := httptest.NewServer(srv)
	t.Cleanup(proxySrv.Close)

	target := mustHostPort(t, upstream.URL)
	host := mustHost(t, upstream.URL)
	conn, err := net.DialTimeout("tcp", mustHostPort(t, proxySrv.URL), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(c.CertPEM())
	tc := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: host})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	var extra strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&extra, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(tc, "GET /headers HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", target, extra.String())
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func decodeBody(t *testing.T, resp *http.Response, b []byte) string {
	t.Helper()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		return string(b)
	}
	zr, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(zr)
	return string(out)
}

func credFixture(t *testing.T, up *httptest.Server) *fixture {
	return newFixture(t, "allow", []creds.Binding{
		{Host: mustHost(t, up.URL), Headers: map[string]string{"Authorization": testSecret}},
	})
}

// SEC-0001: asking for gzip must not smuggle a reflected credential past
// the scrubber.
func TestSEC0001_GzipReflectionScrubbed(t *testing.T) {
	up := reflector()
	defer up.Close()
	f := credFixture(t, up)
	resp, b := tunnel(t, f.srv, f.ca, up, map[string]string{"Accept-Encoding": "gzip"})
	body := decodeBody(t, resp, b)
	if strings.Contains(body, "SECRET") {
		t.Fatalf("credential leaked through gzip response: %q", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %q", body)
	}
}

// A Range request must not return a fragment of a secret that the
// scrubber cannot recognise.
func TestSEC0001_RangeStripped(t *testing.T) {
	up := reflector()
	defer up.Close()
	f := credFixture(t, up)
	resp, b := tunnel(t, f.srv, f.ca, up, map[string]string{"Range": "bytes=10-20"})
	if resp.StatusCode == http.StatusPartialContent {
		t.Fatalf("Range reached upstream on a credentialed request: %q", b)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("credential leaked: %q", b)
	}
}

// A server that encodes without being asked cannot be scrubbed: refuse.
func TestSEC0001_UnsolicitedEncodingRefused(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		io.WriteString(w, "opaque "+r.Header.Get("Authorization"))
	}))
	defer up.Close()
	f := credFixture(t, up)
	resp, b := tunnel(t, f.srv, f.ca, up, nil)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(b), "SECRET") {
		t.Fatalf("want 502 and no secret, got %d %q", resp.StatusCode, b)
	}
}

// Fail-open forwards without a policy decision; it must not inject the
// real credentials into that traffic.
func TestFailOpen_NoCredentialInjection(t *testing.T) {
	var saw string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("Authorization")
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	dir := t.TempDir()
	c, err := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := receipts.LoadOrCreate(filepath.Join(dir, "r.jsonl"), filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	if err != nil {
		t.Fatal(err)
	}
	deadGW := gateway.New("http://127.0.0.1:1", "", "test")
	srv := New(c, deadGW, creds.Load([]creds.Binding{
		{Host: mustHost(t, up.URL), Headers: map[string]string{"Authorization": testSecret}},
	}), chain, true /* fail open */)
	srv.SetPublicEgressOnly(false)
	srv.SetConnectPort443Only(false)

	resp, _ := tunnel(t, srv, c, up, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("fail-open should still forward, got %d", resp.StatusCode)
	}
	if saw != "" {
		t.Fatalf("real credential injected on fail-open path: upstream saw %q", saw)
	}
}

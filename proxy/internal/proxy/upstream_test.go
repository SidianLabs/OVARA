package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// a corporate proxy: answers plain requests itself, tunnels CONNECT
type fakeUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		if r.Method == http.MethodConnect {
			f.seen = append(f.seen, "CONNECT "+r.Host)
		} else {
			f.seen = append(f.seen, r.Method+" "+r.URL.String())
		}
		f.mu.Unlock()
		if r.Method != http.MethodConnect {
			_, _ = w.Write([]byte("via-proxy"))
			return
		}
		dst, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(dst, conn); dst.Close() }()
		_, _ = io.Copy(conn, dst)
		conn.Close()
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeUpstream) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

// With an upstream proxy, Ovara's requests go to it (as a proxy request,
// not a dial of the destination), the destination's name is not resolved
// here, and the proxy's own private address is dialled as given.
func TestUpstreamProxy_RequestsGoThroughItWithoutLocalDNS(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newFakeUpstream(t)
	srv.SetPublicEgressOnly(true)
	if err := srv.SetUpstream(up.URL, nil); err != nil {
		t.Fatal(err)
	}
	rec := send(srv, "GET", "http://example.invalid/x", "", nil, nil)
	if rec.Code != 200 || rec.Body.String() != "via-proxy" {
		t.Fatalf("through the proxy: %d %q", rec.Code, rec.Body.String())
	}
	if l := up.log(); len(l) != 1 || l[0] != "GET http://example.invalid/x" {
		t.Fatalf("the proxy saw %v", l)
	}
	if d := srv.UpstreamDescription(); d != up.URL {
		t.Fatalf("description %q", d)
	}
	// an IP literal that is not public is still Ovara's to refuse
	if rec := send(srv, "GET", "http://10.0.0.5/x", "", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("private literal through the proxy: %d", rec.Code)
	}
	if l := up.log(); len(l) != 1 {
		t.Fatalf("the refused request reached the proxy: %v", l)
	}
}

// TLS to the destination is a CONNECT through the proxy, verified against
// the bundle (a corporate CA) besides the system roots; without the bundle
// the same destination fails verification.
func TestUpstreamProxy_TLSIsTunnelledAndVerifiedAgainstTheBundle(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newFakeUpstream(t)
	dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("tls-ok")) }))
	t.Cleanup(dest.Close)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dest.Certificate().Raw})
	if err := srv.SetUpstream(up.URL, bundle); err != nil {
		t.Fatal(err)
	}
	rec := send(srv, "GET", dest.URL+"/x", "", nil, nil)
	if rec.Code != 200 || rec.Body.String() != "tls-ok" {
		t.Fatalf("tls through the proxy: %d %q", rec.Code, rec.Body.String())
	}
	if l := up.log(); len(l) != 1 || l[0] != "CONNECT "+strings.TrimPrefix(dest.URL, "https://") {
		t.Fatalf("the proxy saw %v", l)
	}
	if err := srv.SetUpstream(up.URL, nil); err != nil {
		t.Fatal(err)
	}
	if rec := send(srv, "GET", dest.URL+"/y", "", nil, nil); rec.Code == 200 {
		t.Fatal("a certificate the bundle no longer vouches for was accepted")
	}
}

func TestSetUpstream_Validation(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	for _, bad := range []string{"corp:3128", "ftp://corp:3128", "http://", "::"} {
		if err := srv.SetUpstream(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := srv.SetUpstream("http://corp.example:3128", []byte("not a certificate")); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("bundle without a certificate: %v", err)
	}
	if err := srv.SetUpstream("http://user:pw@corp.example", nil); err != nil || srv.upstreamHost != "corp.example:80" || srv.UpstreamDescription() != "http://corp.example" {
		t.Errorf("default port and redaction: %v %q %q", err, srv.upstreamHost, srv.UpstreamDescription())
	}
	if !srv.isUpstreamAddr("CORP.example:80") || srv.isUpstreamAddr("corp.example:443") {
		t.Error("isUpstreamAddr")
	}
	if err := srv.SetUpstream("", nil); err != nil || srv.upstreamHost != "" || srv.UpstreamDescription() != "" || srv.transport.Proxy != nil {
		t.Errorf("cleared: %v", err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Logf("no system roots here: %v (SetUpstream falls back to an empty pool)", err)
	}
}

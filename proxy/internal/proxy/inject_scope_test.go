package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.proxy/internal/creds"
)

// tunnelReq is tunnel with a chosen method and path.
func tunnelReq(t *testing.T, srv *Server, upstream *httptest.Server, c interface{ CertPEM() []byte }, method, path string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	srv.transport.TLSClientConfig.RootCAs = pool
	proxySrv := httptest.NewServer(srv)
	t.Cleanup(proxySrv.Close)
	target := mustHostPort(t, upstream.URL)
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
	tc := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: mustHost(t, upstream.URL), MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	var extra strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&extra, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(tc, "%s %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", method, path, target, extra.String())
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

// authRecorder answers 200 and remembers the Authorization header of
// each request path.
type authRecorder struct {
	mu  sync.Mutex
	saw map[string]string
}

func (a *authRecorder) server() *httptest.Server {
	a.saw = map[string]string{}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.saw[r.Method+" "+r.URL.Path] = r.Header.Get("Authorization")
		a.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
}

func (a *authRecorder) get(k string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saw[k]
}

// CR-02: a binding limited to one repository's paths and to GET is not
// attached to other paths or methods on the same host.
func TestPathScopedBindingInjection(t *testing.T) {
	var rec authRecorder
	up := rec.server()
	defer up.Close()
	f := newFixture(t, "allow", []creds.Binding{{
		Host:    mustHostPort(t, up.URL),
		Paths:   []string{"/repos/acme/app", "/repos/acme/app/*"},
		Methods: []string{"GET"},
		Headers: map[string]string{"Authorization": testSecret},
	}})
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/repos/acme/app/contents/x", true},
		{"GET", "/repos/acme/other/contents/x", false},
		{"GET", "/repos/acme/app/..%2F..%2Fother", false},
		{"DELETE", "/repos/acme/app", false},
	} {
		tunnelReq(t, f.srv, up, f.ca, c.method, c.path, nil) //nolint:bodyclose // the helper reads and closes the body
		key := c.method + " " + strings.ReplaceAll(c.path, "%2F", "/")
		if got := rec.get(key) == testSecret; got != c.want {
			t.Errorf("%s %s: credential sent=%v want %v", c.method, c.path, got, c.want)
		}
	}
}

// CR-08: a binding without a port is for 443 only.
func TestBindingWithoutPortNotSentToOtherPort(t *testing.T) {
	var rec authRecorder
	up := rec.server()
	defer up.Close()
	f := newFixture(t, "allow", []creds.Binding{
		{Host: mustHost(t, up.URL), Headers: map[string]string{"Authorization": testSecret}},
	})
	tunnelReq(t, f.srv, up, f.ca, "GET", "/x", nil) //nolint:bodyclose // the helper reads and closes the body
	if got := rec.get("GET /x"); got == testSecret {
		t.Fatal("a binding with no port was used on a non-443 port")
	}
}

// CR-08: an absolute-URI https request obeys the port-443 rule a CONNECT
// does.
func TestPlainProxyHTTPSNon443Refused(t *testing.T) {
	f := newFixture(t, "allow", nil)
	f.srv.SetConnectPort443Only(true)
	req := httptest.NewRequest("GET", "https://127.0.0.1:1/x", nil)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if r := f.lastReceipt(t); r.Decision != gwDeny {
		t.Fatalf("want a deny receipt, got %+v", r)
	}
}

// CR-12: a Connection token naming the injected header does not remove it.
func TestConnectionTokenCannotStripInjectedHeader(t *testing.T) {
	var rec authRecorder
	up := rec.server()
	defer up.Close()
	f := credFixture(t, up)
	tunnelReq(t, f.srv, up, f.ca, "GET", "/x", map[string]string{"Connection": "Authorization"}) //nolint:bodyclose // the helper reads and closes the body
	if got := rec.get("GET /x"); got != testSecret {
		t.Fatalf("injected credential was stripped: upstream saw %q", got)
	}
}

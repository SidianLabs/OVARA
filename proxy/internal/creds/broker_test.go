package creds

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func pkcs1PEM(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func pkcs8PEM(t *testing.T, k any) string {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// fakeClock is a settable time shared by a minter and a fake issuer.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Now()} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeGitHub stands in for POST /app/installations/{id}/access_tokens.
type fakeGitHub struct {
	srv    *httptest.Server
	key    *rsa.PublicKey
	clock  *fakeClock
	calls  atomic.Int32
	fail   atomic.Bool
	delay  time.Duration
	mu     sync.Mutex
	bodies []string
	jwts   []string
}

func newFakeGitHub(t *testing.T, pub *rsa.PublicKey, clock *fakeClock) *fakeGitHub {
	g := &fakeGitHub{key: pub, clock: clock}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/42/access_tokens" {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		n := g.calls.Add(1)
		if g.delay > 0 {
			time.Sleep(g.delay)
		}
		body, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.bodies = append(g.bodies, string(body))
		g.jwts = append(g.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		g.mu.Unlock()
		if g.fail.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"message":"A JSON web token could not be decoded"}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      fmt.Sprintf("ghs_minted%04dXXXXXXXXXXXXXXXXXXXX", n),
			"expires_at": g.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) lastBody() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.bodies[len(g.bodies)-1]
}

// loadGitHubBinding loads one GitHub App binding against the fake.
func loadGitHubBinding(t *testing.T, g *fakeGitHub, host string, app GitHubApp) []Binding { //nolint:unparam // host stays a parameter so tests can bind other hosts
	t.Helper()
	t.Setenv("TEST_GH_APP_ID", "123456")
	t.Setenv("TEST_GH_INSTALL", "42")
	if app.PrivateKey == "" && app.PrivateKeyFile == "" {
		t.Setenv("TEST_GH_APP_KEY", pkcs1PEM(rsaKey(t)))
		app.PrivateKey = "${TEST_GH_APP_KEY}"
	}
	app.AppID = "${TEST_GH_APP_ID}"
	app.InstallationID = "${TEST_GH_INSTALL}"
	app.apiBase = g.srv.URL
	out, skipped, err := LoadReport([]Binding{{Host: host, GitHubApp: &app}})
	if err != nil || len(skipped) > 0 {
		t.Fatalf("load: %v %v", err, skipped)
	}
	for _, b := range out {
		if b.broker != nil {
			b.broker.m.now = g.clock.Now
		}
	}
	return out
}

func rt(g interface{ Client() *http.Client }) http.RoundTripper { return g.Client().Transport }

// The App JWT is RS256, signed with the App key, issued 60 seconds back,
// expiring within 10 minutes, with the App ID as issuer; the token request
// carries the configured repositories and permissions; the token goes out
// as a Bearer header on the API host.
func TestGitHubAppJWTSignedAndDownScoped(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{
		Repositories: []string{"app"},
		Permissions:  map[string]string{"contents": "write", "pull_requests": "write"},
	})
	h, minted, err := bs[0].Credential(context.Background(), rt(g.srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(minted) != 1 || h["Authorization"] != "Bearer "+minted[0] || !strings.HasPrefix(minted[0], "ghs_minted") {
		t.Fatalf("headers %v minted %v", h, minted)
	}
	// Down-scope body.
	var body map[string]any
	if err := json.Unmarshal([]byte(g.lastBody()), &body); err != nil {
		t.Fatal(err)
	}
	want := `{"permissions":{"contents":"write","pull_requests":"write"},"repositories":["app"]}`
	if got, _ := json.Marshal(body); string(got) != want {
		t.Fatalf("token request body %s, want %s", got, want)
	}
	// JWT.
	parts := strings.Split(g.jwts[0], ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("JWT segment not base64url: %v", err)
		}
		return b
	}
	var hdr map[string]string
	_ = json.Unmarshal(dec(parts[0]), &hdr)
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Fatalf("JWT header %v", hdr)
	}
	var claims struct {
		Iat, Exp int64
		Iss      string
	}
	_ = json.Unmarshal(dec(parts[1]), &claims)
	now := clock.Now().Unix()
	if claims.Iss != "123456" || claims.Iat > now-59 || claims.Exp > now+600 || claims.Exp <= now {
		t.Fatalf("JWT claims %+v (now %d)", claims, now)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(g.key, crypto.SHA256, sum[:], dec(parts[2])); err != nil {
		t.Fatalf("JWT signature does not verify with the App's public key: %v", err)
	}
}

// PKCS#1 and PKCS#8 keys load from a file or from the environment; keys
// that are not RSA, or too short, are refused at load.
func TestGitHubAppKeyFormats(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	dir := t.TempDir()
	f := filepath.Join(dir, "app.pem")
	_ = os.WriteFile(f, []byte(pkcs8PEM(t, rsaKey(t))), 0o600)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{PrivateKeyFile: f})
	if _, _, err := bs[0].Credential(context.Background(), rt(g.srv)); err != nil {
		t.Fatalf("PKCS#8 file: %v", err)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	small, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a deliberately weak key the broker must refuse
	for name, pemText := range map[string]string{
		"ec":      pkcs8PEM(t, ec),
		"short":   pkcs1PEM(small),
		"garbage": "not a key",
	} {
		t.Setenv("TEST_BAD_KEY", pemText)
		_, _, err := LoadReport([]Binding{{Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKey: "${TEST_BAD_KEY}"}}})
		if err == nil {
			t.Errorf("%s key: loaded, want an error", name)
		}
	}
}

// A token is reused until 5 minutes before expires_at, then replaced.
func TestGitHubAppTokenRefreshedBeforeExpiry(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{})
	get := func() string {
		_, m, err := bs[0].Credential(context.Background(), rt(g.srv))
		if err != nil {
			t.Fatal(err)
		}
		return m[0]
	}
	first := get()
	clock.Add(54 * time.Minute)
	if get() != first || g.calls.Load() != 1 {
		t.Fatalf("token re-minted %d times before the refresh point", g.calls.Load())
	}
	clock.Add(61 * time.Second) // 55m01s: inside the 5-minute window
	if second := get(); second == first || g.calls.Load() != 2 {
		t.Fatalf("token not replaced inside the refresh window (calls %d)", g.calls.Load())
	}
}

// Concurrent requests that find no token share one mint.
func TestBrokerConcurrentRequestsMintOnce(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	g.delay = 150 * time.Millisecond
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{})
	var wg sync.WaitGroup
	toks := make([]string, 25)
	for i := range toks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, m, err := bs[0].Credential(context.Background(), rt(g.srv))
			if err != nil {
				t.Error(err)
				return
			}
			toks[i] = m[0]
		}(i)
	}
	wg.Wait()
	if n := g.calls.Load(); n != 1 {
		t.Fatalf("%d mints for concurrent requests, want 1", n)
	}
	for _, tok := range toks {
		if tok != toks[0] {
			t.Fatalf("callers got different tokens: %q vs %q", tok, toks[0])
		}
	}
}

// A failed mint is an error, never an empty token; a failed refresh does
// not fall back to the old token; after the back-off a mint is tried again.
func TestBrokerFailureFailsClosed(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{})
	g.fail.Store(true)
	h, m, err := bs[0].Credential(context.Background(), rt(g.srv))
	if !errors.Is(err, ErrCredentialUnavailable) || h != nil || m != nil {
		t.Fatalf("failed mint: headers %v minted %v err %v", h, m, err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error does not say why: %v", err)
	}
	// Within the back-off the issuer is not called again.
	if _, _, err := bs[0].Credential(context.Background(), rt(g.srv)); err == nil || g.calls.Load() != 1 {
		t.Fatalf("back-off: err %v, calls %d", err, g.calls.Load())
	}
	clock.Add(6 * time.Second)
	g.fail.Store(false)
	_, m, err = bs[0].Credential(context.Background(), rt(g.srv))
	if err != nil {
		t.Fatalf("after back-off: %v", err)
	}
	old := m[0]
	// Refresh fails: the old, still-unexpired token is not used.
	clock.Add(56 * time.Minute)
	g.fail.Store(true)
	h, m, err = bs[0].Credential(context.Background(), rt(g.srv))
	if err == nil || h != nil || m != nil {
		t.Fatalf("failed refresh handed out %v %v (old token %s)", h, m, old)
	}
}

// A binding that did not go through LoadReport has no broker and never
// injects anything.
func TestBrokeredBindingNotLoadedRefuses(t *testing.T) {
	b := Binding{Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1"}}
	if _, _, err := b.Credential(context.Background(), http.DefaultTransport); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("want ErrCredentialUnavailable, got %v", err)
	}
}

// A GitHub App binding on api.github.com also covers github.com git
// smart-HTTP, as Basic x-access-token, sharing the one minted token.
func TestGitHubAppGitSmartHTTPBasic(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{})
	b := MatchBinding(bs, Request{Host: "github.com", Method: "POST", Path: "/acme/app.git/git-receive-pack"})
	if b == nil {
		t.Fatal("no binding for github.com")
	}
	h, m, err := b.Credential(context.Background(), rt(g.srv))
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+m[0]))
	if h["Authorization"] != want {
		t.Fatalf("git Authorization %q, want %q", h["Authorization"], want)
	}
	api, _, _ := MatchBinding(bs, Request{Host: "api.github.com", Method: "GET", Path: "/x"}).Credential(context.Background(), rt(g.srv))
	if api["Authorization"] != "Bearer "+m[0] || g.calls.Load() != 1 {
		t.Fatalf("api header %q, mints %d", api["Authorization"], g.calls.Load())
	}
	// A configuration that binds github.com itself gets no companion.
	t.Setenv("TEST_GIT_TOKEN", "a-git-token-of-length")
	out, _, err := LoadReport([]Binding{
		{Host: "api.github.com", GitHubApp: bs[0].GitHubApp},
		{Host: "github.com", Headers: map[string]string{"Authorization": "Bearer ${TEST_GIT_TOKEN}"}},
	})
	if err != nil || len(out) != 2 || out[1].Brokered() {
		t.Fatalf("explicit github.com binding replaced: %v %+v", err, out)
	}
}

// -scope-repo narrows a GitHub App binding that lists no repositories to
// the one repository, on the token itself; listed repositories stay.
func TestScopeBrokersToRepo(t *testing.T) {
	clock := newClock()
	g := newFakeGitHub(t, &rsaKey(t).PublicKey, clock)
	bs := loadGitHubBinding(t, g, "api.github.com", GitHubApp{})
	scoped := ScopeBrokersToRepo(bs, "app")
	for _, h := range []string{"api.github.com", "github.com"} {
		scoped = ScopeToRepo(scoped, h, "acme", "app")
	}
	for _, b := range scoped {
		b.broker.m.now = clock.Now
	}
	b := MatchBinding(scoped, Request{Host: "api.github.com", Method: "GET", Path: "/repos/acme/app/pulls"})
	if b == nil {
		t.Fatal("scoped binding does not match the repository")
	}
	if _, _, err := b.Credential(context.Background(), rt(g.srv)); err != nil {
		t.Fatal(err)
	}
	if got := g.lastBody(); got != `{"repositories":["app"]}` {
		t.Fatalf("token request %s, want the repository", got)
	}
	gb := MatchBinding(scoped, Request{Host: "github.com", Method: "GET", Path: "/acme/app.git/info/refs"})
	if gb == nil {
		t.Fatal("git binding missing after scoping")
	}
	_, _, _ = gb.Credential(context.Background(), rt(g.srv))
	if g.calls.Load() != 1 {
		t.Fatalf("api and git bindings minted %d tokens, want one shared", g.calls.Load())
	}
	if MatchBinding(scoped, Request{Host: "api.github.com", Method: "GET", Path: "/repos/acme/other"}) != nil {
		t.Fatal("scoped binding still matches another repository")
	}
	// The input is not modified; listed repositories are kept.
	if len(bs[0].broker.gh.repos) != 0 {
		t.Fatal("ScopeBrokersToRepo modified its input")
	}
	listed := loadGitHubBinding(t, g, "api.github.com", GitHubApp{Repositories: []string{"docs"}})
	if s := ScopeBrokersToRepo(listed, "app"); s[0].broker != listed[0].broker {
		t.Fatal("a binding that lists repositories was re-scoped")
	}
}

func TestBrokerConfigErrors(t *testing.T) {
	t.Setenv("TEST_K", pkcs1PEM(rsaKey(t)))
	for name, b := range map[string]Binding{
		"both keys":       {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKey: "${TEST_K}", PrivateKeyFile: "/x"}},
		"no key":          {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2"}},
		"no app id":       {Host: "api.github.com", GitHubApp: &GitHubApp{InstallationID: "2", PrivateKey: "${TEST_K}"}},
		"bad install id":  {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "../2", PrivateKey: "${TEST_K}"}},
		"key file absent": {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKeyFile: "/nonexistent/key.pem"}},
		"bad permission":  {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKey: "${TEST_K}", Permissions: map[string]string{"contents": "all"}}},
		"owner in repo":   {Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKey: "${TEST_K}", Repositories: []string{"acme/app"}}},
		"auth header":     {Host: "api.github.com", Headers: map[string]string{"Authorization": "x"}, GitHubApp: &GitHubApp{AppID: "1", InstallationID: "2", PrivateKey: "${TEST_K}"}},
		"both kinds":      {Host: "api.example.com", GitHubApp: &GitHubApp{}, OAuth2: &OAuth2{}},
		"http token url":  {Host: "api.example.com", OAuth2: &OAuth2{TokenURL: "http://auth.example.com/token", ClientID: "c", ClientSecret: "s"}},
		"no secret":       {Host: "api.example.com", OAuth2: &OAuth2{TokenURL: "https://auth.example.com/token", ClientID: "c"}},
		"no subject":      {Host: "api.example.com", OAuth2: &OAuth2{TokenURL: "https://auth.example.com/token", Grant: "token_exchange"}},
		"unknown grant":   {Host: "api.example.com", OAuth2: &OAuth2{TokenURL: "https://auth.example.com/token", Grant: "password"}},
	} {
		if _, _, err := LoadReport([]Binding{b}); err == nil {
			t.Errorf("%s: loaded, want an error", name)
		}
		if c := CheckBroker(b, t.TempDir()); c.Err == nil {
			t.Errorf("%s: CheckBroker found nothing wrong", name)
		}
	}
	// An unset variable skips the binding, as for header bindings.
	out, skipped, err := LoadReport([]Binding{{Host: "api.github.com", GitHubApp: &GitHubApp{AppID: "${TEST_UNSET_APP}", InstallationID: "2", PrivateKey: "${TEST_K}"}}})
	if err != nil || len(out) != 0 || len(skipped) != 1 || skipped[0].Missing[0] != "TEST_UNSET_APP" {
		t.Fatalf("unset variable: out %v skipped %v err %v", out, skipped, err)
	}
	if c := CheckBroker(Binding{Host: "x", GitHubApp: &GitHubApp{AppID: "${TEST_UNSET_APP}"}}, "."); len(c.Missing) == 0 {
		t.Fatal("CheckBroker did not report the unset variable")
	}
}

// fakeOAuth is a token endpoint for both grants.
type fakeOAuth struct {
	srv   *httptest.Server
	calls atomic.Int32
	mu    sync.Mutex
	forms []url.Values
	auths []string
	reply map[string]any
}

func newFakeOAuth(t *testing.T) *fakeOAuth {
	o := &fakeOAuth{reply: map[string]any{"token_type": "Bearer", "expires_in": 3600}}
	o.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := o.calls.Add(1)
		_ = r.ParseForm()
		o.mu.Lock()
		o.forms = append(o.forms, r.PostForm)
		o.auths = append(o.auths, r.Header.Get("Authorization"))
		reply := map[string]any{"access_token": fmt.Sprintf("oauth-access-%04d-XXXXXXXX", n)}
		for k, v := range o.reply {
			reply[k] = v
		}
		o.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func loadOAuthBinding(t *testing.T, o *fakeOAuth, cfg OAuth2, clock *fakeClock) Binding {
	t.Helper()
	cfg.TokenURL = o.srv.URL + "/token"
	out, skipped, err := LoadReport([]Binding{{Host: "api.example.com", OAuth2: &cfg}})
	if err != nil || len(skipped) > 0 || len(out) != 1 {
		t.Fatalf("load: %v %v %v", out, skipped, err)
	}
	out[0].broker.m.now = clock.Now
	return out[0]
}

// Client credentials (RFC 6749 section 4.4): Basic client authentication,
// scope and audience in the form, a Bearer token cached until 60 seconds
// before it expires.
func TestOAuthClientCredentials(t *testing.T) {
	o := newFakeOAuth(t)
	clock := newClock()
	t.Setenv("TEST_OAUTH_ID", "client:1")
	t.Setenv("TEST_OAUTH_SECRET", "s3cr3t/with+chars")
	b := loadOAuthBinding(t, o, OAuth2{ClientID: "${TEST_OAUTH_ID}", ClientSecret: "${TEST_OAUTH_SECRET}", Scope: "read write", Audience: "https://api.example.com"}, clock)
	h, m, err := b.Credential(context.Background(), rt(o.srv))
	if err != nil {
		t.Fatal(err)
	}
	if h["Authorization"] != "Bearer "+m[0] {
		t.Fatalf("header %q", h["Authorization"])
	}
	f := o.forms[0]
	if f.Get("grant_type") != "client_credentials" || f.Get("scope") != "read write" || f.Get("audience") != "https://api.example.com" || f.Get("client_secret") != "" {
		t.Fatalf("form %v", f)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("client:1")+":"+url.QueryEscape("s3cr3t/with+chars")))
	if o.auths[0] != wantAuth {
		t.Fatalf("client auth %q, want %q", o.auths[0], wantAuth)
	}
	clock.Add(3539 * time.Second)
	if _, m2, _ := b.Credential(context.Background(), rt(o.srv)); m2[0] != m[0] || o.calls.Load() != 1 {
		t.Fatal("token re-minted before expiry-60s")
	}
	clock.Add(2 * time.Second)
	if _, m3, _ := b.Credential(context.Background(), rt(o.srv)); m3[0] == m[0] || o.calls.Load() != 2 {
		t.Fatal("token not replaced 60s before expiry")
	}
}

// Token exchange (RFC 8693): the subject token and its type, the audience,
// and client authentication in the form when client_auth is "post".
func TestOAuthTokenExchange(t *testing.T) {
	o := newFakeOAuth(t)
	clock := newClock()
	t.Setenv("TEST_SUBJECT", "subject-token-long-lived")
	b := loadOAuthBinding(t, o, OAuth2{Grant: "token_exchange", SubjectToken: "${TEST_SUBJECT}", Audience: "svc", ClientID: "cid", ClientSecret: "csecret", ClientAuth: "post"}, clock)
	if _, _, err := b.Credential(context.Background(), rt(o.srv)); err != nil {
		t.Fatal(err)
	}
	f := o.forms[0]
	if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		f.Get("subject_token") != "subject-token-long-lived" ||
		f.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
		f.Get("audience") != "svc" || f.Get("client_id") != "cid" || f.Get("client_secret") != "csecret" || o.auths[0] != "" {
		t.Fatalf("form %v auth %q", f, o.auths[0])
	}
}

// A token type other than Bearer, or an error answer, is refused.
func TestOAuthRefusesUnusableAnswers(t *testing.T) {
	o := newFakeOAuth(t)
	clock := newClock()
	b := loadOAuthBinding(t, o, OAuth2{ClientID: "c", ClientSecret: "s"}, clock)
	o.reply["token_type"] = "N_A"
	if _, _, err := b.Credential(context.Background(), rt(o.srv)); err == nil {
		t.Fatal("non-Bearer token accepted")
	}
	clock.Add(10 * time.Second)
	o.reply["token_type"] = "bearer"
	o.reply["access_token"] = "short"
	if _, _, err := b.Credential(context.Background(), rt(o.srv)); err == nil {
		t.Fatal("token too short to scrub accepted")
	}
}

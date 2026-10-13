package creds

// Credential broker: a binding that holds a long-lived secret (a GitHub App
// private key, an OAuth client secret) and injects a short-lived token
// minted from it, scoped down to what the run needs. The long-lived secret
// stays in Ovara's environment; only the minted token goes upstream, and
// only on requests the binding matches.

import (
	"bytes"
	"context"
	"crypto"
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
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// GitHubApp mints GitHub App installation tokens: an RS256 JWT signed with
// the App's private key is exchanged at
// POST /app/installations/{id}/access_tokens for a token that lives one
// hour and can be limited to some repositories and permissions.
//
// On an "api." host the token goes out as "Authorization: Bearer <token>";
// on any other host (github.com git smart-HTTP) as Basic
// "x-access-token:<token>".
type GitHubApp struct {
	AppID          string `json:"app_id"`          // App ID or client ID (the JWT issuer)
	InstallationID string `json:"installation_id"` // numeric installation ID
	// Exactly one of PrivateKeyFile (a PEM file, PKCS#1 or PKCS#8) and
	// PrivateKey (the PEM text, usually "${GH_APP_KEY}").
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	// Repositories limits the token to these repositories of the
	// installation (names, without the owner). Empty: every repository the
	// installation can reach, unless `ovara run -scope-repo` names one.
	Repositories []string `json:"repositories,omitempty"`
	// Permissions limits the token to these permissions ("contents":
	// "read"), each no more than the App itself was granted. Empty: all
	// of the App's permissions.
	Permissions map[string]string `json:"permissions,omitempty"`

	apiBase string // tests only; "" is https://api.github.com
}

// OAuth2 mints access tokens at an OAuth 2.0 token endpoint, by the client
// credentials grant (RFC 6749 section 4.4) or by token exchange (RFC 8693).
// The token is injected as "Authorization: Bearer <token>".
type OAuth2 struct {
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientAuth is how the client authenticates: "basic" (HTTP Basic,
	// the default) or "post" (client_id and client_secret in the form).
	ClientAuth string `json:"client_auth,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Audience   string `json:"audience,omitempty"`
	Resource   string `json:"resource,omitempty"`
	// Grant is "client_credentials" (the default) or "token_exchange".
	Grant string `json:"grant,omitempty"`
	// SubjectToken is the token exchanged (token_exchange only), with its
	// type (default urn:ietf:params:oauth:token-type:access_token).
	SubjectToken     string `json:"subject_token,omitempty"`
	SubjectTokenType string `json:"subject_token_type,omitempty"`
}

const (
	githubAPIBase = "https://api.github.com"
	// githubRefresh is how long before expires_at a GitHub token is
	// replaced; oauthRefresh the same for OAuth tokens.
	githubRefresh = 5 * time.Minute
	oauthRefresh  = 60 * time.Second
	// oauthDefaultLife is assumed when a token response has no expires_in.
	oauthDefaultLife = 2 * oauthRefresh
	// mintBackoff is how long a failed mint is remembered: requests in
	// that window are refused at once instead of each calling the issuer.
	mintBackoff      = 5 * time.Second
	mintTimeout      = 30 * time.Second
	maxTokenResponse = 64 << 10

	clientAuthPost         = "post"
	grantClientCredentials = "client_credentials"
	grantTokenExchange     = "token_exchange"
	tokenExchangeURN       = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // an RFC 8693 grant type name, not a credential
	accessTokenTypeURN     = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // an RFC 8693 token type name, not a credential
)

// ErrCredentialUnavailable wraps every reason a brokered binding has no
// token to inject. The request it was for must not be sent.
var ErrCredentialUnavailable = errors.New("short-lived credential unavailable")

// Brokered reports whether the binding injects a minted token rather than
// fixed headers.
func (b Binding) Brokered() bool { return b.GitHubApp != nil || b.OAuth2 != nil }

// Credential returns the headers to inject for a request the binding
// matched, and the minted token values among them (to be scrubbed from the
// response like any injected secret). For a brokered binding it mints or
// reuses a token; rt carries Ovara's own call to the issuer and must be a
// verified-TLS transport that does not pass through policy. An error means
// nothing may be injected and the request must not be sent: a brokered
// binding never falls back to an empty or expired token.
func (b Binding) Credential(ctx context.Context, rt http.RoundTripper) (map[string]string, []string, error) {
	if !b.Brokered() {
		return b.Headers, nil, nil
	}
	if b.broker == nil {
		return nil, nil, fmt.Errorf("%w: binding for %s was not loaded", ErrCredentialUnavailable, b.Host)
	}
	tok, err := b.broker.m.token(ctx, rt)
	if err != nil {
		return nil, nil, fmt.Errorf("%w for %s: %v", ErrCredentialUnavailable, b.Host, err)
	}
	h := make(map[string]string, len(b.Headers)+1)
	for k, v := range b.Headers {
		h[k] = v
	}
	if b.GitHubApp != nil && !strings.HasPrefix(hostOnly(b.Host), "api.") {
		h["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
	} else {
		h["Authorization"] = "Bearer " + tok
	}
	return h, []string{tok}, nil
}

// Describe says, for logs, what a brokered binding mints. It never
// contains a secret.
func (b Binding) Describe() string {
	switch {
	case b.broker != nil:
		return b.broker.desc
	case b.GitHubApp != nil:
		return "GitHub App installation tokens"
	case b.OAuth2 != nil:
		return "OAuth 2.0 access tokens"
	}
	return ""
}

func hostOnly(pat string) string {
	h, _ := splitHostPattern(pat)
	return h
}

// broker is the loaded form of a brokered binding: expanded settings, the
// parsed key and the token cache. Bindings copied from one share it.
type broker struct {
	m    *minter
	desc string
	gh   *ghConfig
}

type ghConfig struct {
	appID, installation string
	key                 *rsa.PrivateKey
	repos               []string
	perms               map[string]string
	base                string
}

var (
	installationIDRe = regexp.MustCompile(`^[0-9]{1,20}$`)
	permNameRe       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	repoNameRe       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// expander expands ${VAR} from the environment and records unset ones.
type expander struct{ missing []string }

func (e *expander) expand(s string) string {
	return os.Expand(s, func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			e.missing = append(e.missing, name)
		}
		return v
	})
}

// BrokerCheck is what `ovara doctor` learns about a brokered binding
// without calling the issuer: variables it needs that are unset, the key
// file it reads (GitHub App), and the first configuration error.
type BrokerCheck struct {
	Missing []string
	KeyFile string
	Err     error
}

// CheckBroker validates a brokered binding's settings offline: required
// fields, the private key (read and parsed), the token URL. It makes no
// network call. A relative private_key_file is taken relative to dir (the
// deployment directory `ovara run` works in).
func CheckBroker(b Binding, dir string) BrokerCheck {
	var c BrokerCheck
	all := &expander{}
	brokerEnv(b, all)
	c.Missing = all.missing
	if b.GitHubApp != nil && b.GitHubApp.PrivateKeyFile != "" {
		c.KeyFile = os.Expand(b.GitHubApp.PrivateKeyFile, os.Getenv)
		if c.KeyFile != "" && !filepath.IsAbs(c.KeyFile) {
			c.KeyFile = filepath.Join(dir, c.KeyFile)
		}
		g := *b.GitHubApp
		g.PrivateKeyFile = c.KeyFile
		b.GitHubApp = &g
	}
	if len(c.Missing) == 0 {
		_, c.Err = loadBroker(b, &expander{})
	}
	return c
}

// brokerEnv expands every templated field once, to collect missing names.
func brokerEnv(b Binding, e *expander) {
	if g := b.GitHubApp; g != nil {
		for _, s := range []string{g.AppID, g.InstallationID, g.PrivateKeyFile, g.PrivateKey} {
			e.expand(s)
		}
	}
	if o := b.OAuth2; o != nil {
		for _, s := range []string{o.TokenURL, o.ClientID, o.ClientSecret, o.Scope, o.Audience, o.Resource, o.SubjectToken} {
			e.expand(s)
		}
	}
}

// loadBroker builds the broker for a brokered binding. Unset variables are
// reported through e (the binding is then skipped); anything else wrong is
// an error that stops startup.
func loadBroker(b Binding, e *expander) (*broker, error) {
	if b.GitHubApp != nil && b.OAuth2 != nil {
		return nil, fmt.Errorf("credential binding for %s: github_app and oauth2 cannot both be set", b.Host)
	}
	for k := range b.Headers {
		if strings.EqualFold(k, "Authorization") {
			return nil, fmt.Errorf("credential binding for %s: a brokered binding sets Authorization itself; remove it from headers", b.Host)
		}
	}
	if b.GitHubApp != nil {
		return loadGitHubApp(b, e)
	}
	return loadOAuth2(b, e)
}

func loadGitHubApp(b Binding, e *expander) (*broker, error) {
	g := b.GitHubApp
	where := "credential binding for " + b.Host + " (github_app)"
	cfg := &ghConfig{
		appID:        strings.TrimSpace(e.expand(g.AppID)),
		installation: strings.TrimSpace(e.expand(g.InstallationID)),
		base:         g.apiBase,
	}
	if cfg.base == "" {
		cfg.base = githubAPIBase
	}
	keyFile := e.expand(g.PrivateKeyFile)
	keyText := e.expand(g.PrivateKey)
	if len(e.missing) > 0 {
		return nil, nil
	}
	if cfg.appID == "" {
		return nil, fmt.Errorf("%s: app_id is required", where)
	}
	if !installationIDRe.MatchString(cfg.installation) {
		return nil, fmt.Errorf("%s: installation_id must be the numeric installation ID", where)
	}
	if (g.PrivateKeyFile == "") == (g.PrivateKey == "") {
		return nil, fmt.Errorf("%s: set exactly one of private_key_file and private_key", where)
	}
	var pemBytes []byte
	if g.PrivateKeyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("%s: private_key_file: %v", where, err)
		}
		pemBytes = raw
	} else {
		pemBytes = []byte(keyText)
	}
	key, err := parseRSAKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: private key: %v", where, err)
	}
	cfg.key = key
	for _, r := range g.Repositories {
		if !repoNameRe.MatchString(r) {
			return nil, fmt.Errorf("%s: repository %q: give the repository name only, without the owner", where, r)
		}
		cfg.repos = append(cfg.repos, r)
	}
	if len(g.Permissions) > 0 {
		cfg.perms = make(map[string]string, len(g.Permissions))
		for k, v := range g.Permissions {
			if !permNameRe.MatchString(k) {
				return nil, fmt.Errorf("%s: permission name %q is not valid", where, k)
			}
			switch v {
			case "read", "write", "admin":
			default:
				return nil, fmt.Errorf("%s: permission %s=%q: want read, write or admin", where, k, v)
			}
			cfg.perms[k] = v
		}
	}
	return newGitHubBroker(cfg), nil
}

func newGitHubBroker(cfg *ghConfig) *broker {
	desc := "GitHub App installation " + cfg.installation + " tokens"
	if len(cfg.repos) > 0 {
		desc += ", repositories: " + strings.Join(cfg.repos, ",")
	} else {
		desc += ", every repository of the installation"
	}
	if len(cfg.perms) > 0 {
		var ps []string
		for k, v := range cfg.perms {
			ps = append(ps, k+"="+v)
		}
		sort.Strings(ps)
		desc += ", permissions: " + strings.Join(ps, ",")
	}
	return &broker{
		desc: desc,
		gh:   cfg,
		m: &minter{
			refresh: githubRefresh,
			what:    "GitHub App installation " + cfg.installation,
			fetch:   cfg.mint,
		},
	}
}

// parseRSAKey reads an unencrypted PEM RSA private key, PKCS#1 or PKCS#8.
func parseRSAKey(data []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(bytes.TrimSpace(data))
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	if _, enc := blk.Headers["Proc-Type"]; enc {
		return nil, errors.New("encrypted PEM keys are not supported")
	}
	var key *rsa.PrivateKey
	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("the PKCS#8 key is not an RSA key")
		}
		key = rk
	default:
		return nil, fmt.Errorf("unexpected PEM block %q (want RSA PRIVATE KEY or PRIVATE KEY)", blk.Type)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key of %d bits is too short (want at least 2048)", key.N.BitLen())
	}
	return key, nil
}

// appJWT is the RS256 JWT a GitHub App authenticates with: issued 60
// seconds in the past (clock drift), expiring 9 minutes from now (GitHub
// refuses more than 10).
func (c *ghConfig) appJWT(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.appID,
	})
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// mint asks GitHub for an installation token limited to the configured
// repositories and permissions.
func (c *ghConfig) mint(ctx context.Context, rt http.RoundTripper, now time.Time) (string, time.Time, error) {
	jwt, err := c.appJWT(now)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing the App JWT: %v", err)
	}
	body := map[string]any{}
	if len(c.repos) > 0 {
		body["repositories"] = c.repos
	}
	if len(c.perms) > 0 {
		body["permissions"] = c.perms
	}
	raw, _ := json.Marshal(body)
	u := strings.TrimRight(c.base, "/") + "/app/installations/" + c.installation + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ovara-credential-broker")
	status, data, err := roundTrip(rt, req)
	if err != nil {
		return "", time.Time{}, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("GitHub answered %d%s", status, issuerMessage(data, "message"))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", time.Time{}, errors.New("GitHub's token response is not valid JSON")
	}
	if out.ExpiresAt.IsZero() {
		return "", time.Time{}, errors.New("GitHub's token response has no expires_at")
	}
	return out.Token, out.ExpiresAt, nil
}

func loadOAuth2(b Binding, e *expander) (*broker, error) {
	o := b.OAuth2
	where := "credential binding for " + b.Host + " (oauth2)"
	c := &oauthConfig{
		tokenURL:     e.expand(o.TokenURL),
		clientID:     e.expand(o.ClientID),
		clientSecret: e.expand(o.ClientSecret),
		clientAuth:   o.ClientAuth,
		scope:        e.expand(o.Scope),
		audience:     e.expand(o.Audience),
		resource:     e.expand(o.Resource),
		grant:        o.Grant,
		subject:      e.expand(o.SubjectToken),
		subjectType:  o.SubjectTokenType,
	}
	if len(e.missing) > 0 {
		return nil, nil
	}
	u, err := url.Parse(c.tokenURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%s: token_url must be an https:// URL", where)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: token_url must not carry credentials", where)
	}
	switch c.grant {
	case "", grantClientCredentials:
		c.grant = grantClientCredentials
		if c.clientID == "" || c.clientSecret == "" {
			return nil, fmt.Errorf("%s: client_credentials needs client_id and client_secret", where)
		}
	case grantTokenExchange:
		if c.subject == "" {
			return nil, fmt.Errorf("%s: token_exchange needs subject_token", where)
		}
		if c.subjectType == "" {
			c.subjectType = accessTokenTypeURN
		}
	default:
		return nil, fmt.Errorf("%s: grant %q: want client_credentials or token_exchange", where, c.grant)
	}
	switch c.clientAuth {
	case "", "basic", clientAuthPost:
	default:
		return nil, fmt.Errorf("%s: client_auth %q: want basic or post", where, c.clientAuth)
	}
	if c.clientSecret != "" && c.clientID == "" {
		return nil, fmt.Errorf("%s: client_secret without client_id", where)
	}
	desc := "OAuth 2.0 " + strings.ReplaceAll(c.grant, "_", " ") + " tokens from " + u.Host
	if c.scope != "" {
		desc += ", scope: " + c.scope
	}
	return &broker{
		desc: desc,
		m:    &minter{refresh: oauthRefresh, what: "OAuth token from " + u.Host, fetch: c.mint},
	}, nil
}

type oauthConfig struct {
	tokenURL, clientID, clientSecret, clientAuth string
	scope, audience, resource                    string
	grant, subject, subjectType                  string
}

func (c *oauthConfig) mint(ctx context.Context, rt http.RoundTripper, now time.Time) (string, time.Time, error) {
	form := url.Values{}
	if c.grant == grantTokenExchange {
		form.Set("grant_type", tokenExchangeURN)
		form.Set("subject_token", c.subject)
		form.Set("subject_token_type", c.subjectType)
	} else {
		form.Set("grant_type", "client_credentials")
	}
	for k, v := range map[string]string{"scope": c.scope, "audience": c.audience, "resource": c.resource} {
		if v != "" {
			form.Set(k, v)
		}
	}
	if c.clientID != "" && c.clientAuth == clientAuthPost {
		form.Set("client_id", c.clientID)
		if c.clientSecret != "" {
			form.Set("client_secret", c.clientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ovara-credential-broker")
	if c.clientID != "" && c.clientAuth != clientAuthPost {
		// RFC 6749 section 2.3.1: form-encode both parts before Basic.
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	}
	status, data, err := roundTrip(rt, req)
	if err != nil {
		return "", time.Time{}, err
	}
	if status != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token endpoint answered %d%s", status, issuerMessage(data, "error"))
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", time.Time{}, errors.New("token response is not valid JSON")
	}
	if !strings.EqualFold(out.TokenType, "bearer") {
		return "", time.Time{}, fmt.Errorf("token type %q is not supported (only Bearer)", printable(out.TokenType))
	}
	life := oauthDefaultLife
	if s := strings.Trim(string(out.ExpiresIn), `"`); s != "" && s != "null" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return "", time.Time{}, errors.New("token response has an invalid expires_in")
		}
		life = time.Duration(n) * time.Second
	}
	return out.AccessToken, now.Add(life), nil
}

// roundTrip sends Ovara's own request to an issuer: on rt directly (no
// redirects followed, no proxy, no policy), with a bounded response.
func roundTrip(rt http.RoundTripper, req *http.Request) (int, []byte, error) {
	if rt == nil {
		return 0, nil, errors.New("no transport for the issuer call")
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return 0, nil, fmt.Errorf("calling %s: %v", req.URL.Host, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return 0, nil, fmt.Errorf("reading the answer from %s: %v", req.URL.Host, err)
	}
	if len(data) > maxTokenResponse {
		return 0, nil, fmt.Errorf("the answer from %s is too large", req.URL.Host)
	}
	return resp.StatusCode, data, nil
}

// issuerMessage pulls a short, printable explanation out of an error
// answer, for the operator's log.
func issuerMessage(data []byte, field string) string {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	s, _ := m[field].(string)
	if s == "" {
		return ""
	}
	return ": " + printable(s)
}

func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// minter caches one token and replaces it before it expires. Concurrent
// callers that find no usable token share a single mint. A token is never
// handed out after (expiry - refresh); a failed mint is never covered by
// an older token.
type minter struct {
	refresh time.Duration
	what    string
	fetch   func(ctx context.Context, rt http.RoundTripper, now time.Time) (string, time.Time, error)
	now     func() time.Time // tests

	mu       sync.Mutex
	tok      string
	exp      time.Time
	inflight *mintCall
	failErr  error
	failAt   time.Time
}

type mintCall struct {
	done chan struct{}
	tok  string
	err  error
}

func (m *minter) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *minter) token(ctx context.Context, rt http.RoundTripper) (string, error) {
	m.mu.Lock()
	now := m.clock()
	if m.tok != "" && now.Before(m.exp.Add(-m.refresh)) {
		t := m.tok
		m.mu.Unlock()
		return t, nil
	}
	if m.failErr != nil && now.Sub(m.failAt) < mintBackoff {
		err := m.failErr
		m.mu.Unlock()
		return "", err
	}
	c := m.inflight
	if c == nil {
		c = &mintCall{done: make(chan struct{})}
		m.inflight = c
		// Detached from the caller: one impatient client must not abort
		// the mint every other waiting request depends on.
		go m.run(c, rt)
	}
	m.mu.Unlock()
	select {
	case <-c.done:
		return c.tok, c.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (m *minter) run(c *mintCall, rt http.RoundTripper) {
	ctx, cancel := context.WithTimeout(context.Background(), mintTimeout)
	defer cancel()
	start := m.clock()
	tok, exp, err := m.fetch(ctx, rt, start)
	if err == nil {
		switch {
		case len(tok) < MinSecretLen:
			err = errors.New("the issuer returned no usable token")
		case !exp.After(m.clock()):
			err = errors.New("the issuer returned a token that has already expired")
		}
	}
	m.mu.Lock()
	m.inflight = nil
	if err != nil {
		// The old token is dropped too: after a failed refresh nothing is
		// injected until a mint succeeds.
		m.tok, m.exp = "", time.Time{}
		m.failErr, m.failAt = err, m.clock()
	} else {
		m.tok, m.exp = tok, exp
		m.failErr = nil
	}
	m.mu.Unlock()
	if err != nil {
		log.Printf("credential broker: minting %s failed: %v", m.what, err)
	} else {
		log.Printf("credential broker: minted a short-lived token (%s), valid until %s", m.what, exp.UTC().Format(time.RFC3339))
		c.tok = tok
	}
	c.err = err
	close(c.done)
}

// ScopeBrokersToRepo limits GitHub App bindings that list no repositories
// to repo (a name, without the owner), so `-scope-repo` narrows the minted
// token itself and not only the requests it is attached to. Bindings that
// shared a broker keep sharing the narrowed one. The input is not
// modified.
func ScopeBrokersToRepo(bindings []Binding, repo string) []Binding {
	if !repoNameRe.MatchString(repo) {
		return bindings
	}
	scoped := map[*broker]*broker{}
	out := make([]Binding, len(bindings))
	for i, b := range bindings {
		out[i] = b
		if b.GitHubApp == nil || b.broker == nil || b.broker.gh == nil || len(b.broker.gh.repos) > 0 {
			continue
		}
		nb, ok := scoped[b.broker]
		if !ok {
			cfg := *b.broker.gh
			cfg.repos = []string{repo}
			nb = newGitHubBroker(&cfg)
			scoped[b.broker] = nb
		}
		out[i].broker = nb
	}
	return out
}

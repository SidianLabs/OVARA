package identity

// P1.1 delegation red-team: cryptographic soundness + capability
// semantics. Signed canonical payloads, terminal-hop replay nonce,
// restricted scope grammar, non-amplification, terminal enforcement.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type delegKeys struct {
	pub  map[string][]byte
	priv map[string]ed25519.PrivateKey
}

func newDelegKeys(t *testing.T, issuers ...string) *delegKeys {
	t.Helper()
	k := &delegKeys{pub: map[string][]byte{}, priv: map[string]ed25519.PrivateKey{}}
	for _, iss := range issuers {
		p, s, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		k.pub[iss], k.priv[iss] = p, s
	}
	return k
}

func mintChain(k *delegKeys, hops []models.Authority) *models.DelegationChain {
	c := &models.DelegationChain{Authorities: hops, Depth: len(hops)}
	signHops(c, k.priv)
	return c
}

func validHop(issuer, subject string) models.Authority {
	return models.Authority{
		Issuer: issuer, SubjectID: subject,
		Actions: []string{"shell"}, ResourceScope: "repo://org/*",
		ExpiresAt: time.Now().Add(time.Hour), DelegatedAt: time.Now(),
		Nonce: "n-" + issuer + "-" + subject,
	}
}

// DELEG-01 valid signed delegation
func TestDeleg_ValidChain(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(k, []models.Authority{validHop("root", "ag_abc")})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); !r.Valid {
		t.Fatalf("valid chain rejected: %v", r.Reasons)
	}
}

// DELEG-02 forged issuer (signed by non-registry key)
func TestDeleg_ForgedIssuer(t *testing.T) {
	k := newDelegKeys(t, "root")
	evil := newDelegKeys(t, "root") // same issuer id, different key
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(evil, []models.Authority{validHop("root", "ag_abc")})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("forged-issuer signature must not validate")
	}
}

// DELEG-03 unknown issuer
func TestDeleg_UnknownIssuer(t *testing.T) {
	k := newDelegKeys(t, "root")
	evil := newDelegKeys(t, "evil-issuer")
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(evil, []models.Authority{validHop("evil-issuer", "ag_abc")})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("unknown issuer must not validate")
	}
}

// DELEG-04..10: post-signature mutation invalidates (canonical payload
// covers every asserted field).
func TestDeleg_MutationsInvalidate(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	mutants := []struct {
		name string
		mut  func(*models.Authority)
	}{
		{"04 signature bytes", func(a *models.Authority) { a.Signature[0] ^= 0xff }},
		{"05 subject", func(a *models.Authority) { a.SubjectID = "ag_evil" }},
		{"06 audience", func(a *models.Authority) { a.Audience = "gw-other" }},
		{"07 action", func(a *models.Authority) { a.Actions = []string{"exec"} }},
		{"08 resource", func(a *models.Authority) { a.ResourceScope = "repo://evil/*" }},
		{"09 expiry", func(a *models.Authority) { a.ExpiresAt = a.ExpiresAt.Add(time.Hour) }},
		{"10 nonce", func(a *models.Authority) { a.Nonce = "mutated" }},
	}
	for _, m := range mutants {
		c := mintChain(k, []models.Authority{validHop("root", "ag_abc")})
		m.mut(&c.Authorities[0])
		if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
			t.Fatalf("%s: mutated hop must not validate", m.name)
		}
	}
}

// DELEG-11 replay same delegation → second presentation denied.
func TestDeleg_Replay(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(k, []models.Authority{validHop("root", "ag_abc")})
	seen := map[string]bool{}
	seenFn := func(n string, _ time.Time) NonceMark {
		if seen[n] {
			return NonceMarkSeen
		}
		seen[n] = true
		return NonceMarkFirst
	}
	if r := v.ValidateDelegationChain(c, "ag_abc", seenFn); !r.Valid {
		t.Fatalf("first presentation rejected: %v", r.Reasons)
	}
	if r := v.ValidateDelegationChain(c, "ag_abc", seenFn); r.Valid {
		t.Fatal("replayed chain must not validate")
	}
}

// DELEG-12 replay after nonce MUTATION — now impossible: the nonce is
// signed; mutating it breaks the signature (proven by TestDeleg_Mutations
// case 10). Double-cover: a mutated-nonce chain can't even reach the
// replay check.
func TestDeleg_ReplayNonceMutation(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(k, []models.Authority{validHop("root", "ag_abc")})
	seen := map[string]bool{}
	seenFn := func(n string, _ time.Time) NonceMark {
		if seen[n] {
			return NonceMarkSeen
		}
		seen[n] = true
		return NonceMarkFirst
	}
	_ = v.ValidateDelegationChain(c, "ag_abc", seenFn)
	c.Authorities[0].Nonce = "nn-evil" // mutate the SIGNED nonce
	if r := v.ValidateDelegationChain(c, "ag_abc", seenFn); r.Valid {
		t.Fatal("nonce-mutated replay must not validate")
	}
}

// DELEG-13 same nonce, different payload: issuer re-uses a nonce across
// different signed chains — both are *valid signatures*; the second is
// caught by the replay check (issuer-scoped nonce space).
func TestDeleg_SameNonceDifferentPayload(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	seen := map[string]bool{}
	seenFn := func(n string, _ time.Time) NonceMark {
		if seen[n] {
			return NonceMarkSeen
		}
		seen[n] = true
		return NonceMarkFirst
	}
	h1 := validHop("root", "ag_abc")
	h1.Nonce = "shared"
	h2 := validHop("root", "ag_xyz")
	h2.Nonce = "shared" // same nonce, different subject
	_ = v.ValidateDelegationChain(mintChain(k, []models.Authority{h1}), "ag_abc", seenFn)
	if r := v.ValidateDelegationChain(mintChain(k, []models.Authority{h2}), "ag_xyz", seenFn); r.Valid {
		t.Fatal("issuer nonce reuse across chains must be caught by replay cache")
	}
}

// DELEG-14/15/16/17/18 non-amplification (see also scope tests below).
func TestDeleg_ActionExpansion(t *testing.T) {
	k := newDelegKeys(t, "root", "mid")
	v := NewValidatorWithTrustedKeys(k.pub)
	h0 := validHop("root", "mid")
	h0.Actions = []string{"shell"}
	h1 := validHop("mid", "ag_abc")
	h1.Actions = []string{"shell", "exec"}
	c := mintChain(k, []models.Authority{h0, h1})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("action expansion must not validate")
	}
}

func TestDeleg_ExpiryExpansion(t *testing.T) {
	k := newDelegKeys(t, "root", "mid")
	v := NewValidatorWithTrustedKeys(k.pub)
	h0 := validHop("root", "mid")
	h0.ExpiresAt = time.Now().Add(time.Hour)
	h1 := validHop("mid", "ag_abc")
	h1.ExpiresAt = time.Now().Add(2 * time.Hour)
	c := mintChain(k, []models.Authority{h0, h1})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("expiry expansion must not validate")
	}
}

func TestDeleg_AudienceExpansion(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	v.SetExpectedAudience("gw-A")
	h := validHop("root", "ag_abc")
	h.Audience = "gw-B"
	c := mintChain(k, []models.Authority{h})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("wrong-audience delegation must not validate")
	}
}

// DELEG-19..28: scope grammar — the restricted grammar must reject every
// smuggling form, not just the three original bypasses.
func TestDeleg_ScopeGrammar(t *testing.T) {
	rejects := []string{
		"https://evil.example/?u=https://api.github.com/", // query smuggle (query in scope rejected anyway + different host)
		"evil://x repo://org/",                            // scheme-wrap
		"repo://org/../etc",                               // traversal (dot segment)
		"repo://org/a/../b",                               // embedded traversal
		"https://user@api.github.com/*",                   // userinfo
		"https://api.github.com/*rest*",                   // mid-string star
		"https://api.github.com/**",                       // double star — lit "*"→ contains '*' after strip → reject
		"https://api.github.com/pa*th",                    // star mid-path
		"https://api.github.com/p?q=*",                    // query in scope
		"https://api.github.com/p#f",                      // fragment in scope
	}
	for _, s := range rejects {
		if validScope(s) {
			t.Errorf("invalid scope grammar accepted: %q", s)
		}
	}
	accepts := []string{
		"*", "https://api.github.com/*", "https://api.github.com/repos/*",
		"https://api.github.com/exact/path", "repo://org/*",
		"cmd:deploy-*", "literal-resource",
		"https://api.github.com:443/*", // explicit default port
	}
	for _, s := range accepts {
		if !validScope(s) {
			t.Errorf("valid scope rejected: %q", s)
		}
	}
}

// The three proven F-3 bypasses — must be REJECTED as subsets.
func TestDeleg_ScopeContainment_BypassRegressions(t *testing.T) {
	bypasses := []struct{ parent, child string }{
		{"https://api.github.com/*", "https://evil.example/?u=https://api.github.com/"},
		{"repo://org/*", "evil://x repo://org/"},
		{"repo://org/*", "repo://org/../etc"},
	}
	for _, b := range bypasses {
		if scopeContains(b.parent, b.child) {
			t.Errorf("BYPASS: %q accepted as subset of %q", b.child, b.parent)
		}
	}
	// Legitimate narrowing must still pass.
	legit := []struct{ parent, child string }{
		{"*", "https://api.github.com/*"},
		{"https://api.github.com/*", "https://api.github.com/repos/*"},
		{"https://api.github.com/*", "https://api.github.com/exact"},
		{"repo://org/*", "repo://org/sub/*"},
		{"cmd:deploy-*", "cmd:deploy-prod"},
		{"exact", "exact"},
		{"https://api.github.com/*", "https://api.github.com:443/x"}, // default port normalizes
	}
	for _, b := range legit {
		if !scopeContains(b.parent, b.child) {
			t.Errorf("legitimate narrowing rejected: %q ⊆ %q", b.child, b.parent)
		}
	}
}

// scopeMatches — terminal enforcement matching.
func TestDeleg_ScopeMatches(t *testing.T) {
	cases := []struct {
		scope, resource string
		want            bool
	}{
		{"*", "anything", true},
		{"https://api.github.com/*", "https://api.github.com/x", true},
		{"https://api.github.com/*", "https://api.github.com/x?y=1", true},
		{"https://api.github.com/*", "https://evil.example/x", false},
		{"https://api.github.com/*", "HTTPS://API.GITHUB.COM/x", true}, // case-normalized
		{"https://api.github.com:443/*", "https://api.github.com/x", true},
		{"https://api.github.com/*", "https://api.github.com:8443/x", false}, // port confusion
		{"repo://org/*", "repo://org/repo1", true},
		{"repo://org/*", "repo://evil/repo1", false},
		{"repo://org/*", "repo://org/../etc", false},   // dot-segment resources rejected outright (fail closed)
		{"repo://org/a/*", "repo://org/../etc", false}, // canon repo://org/etc is NOT under repo://org/a/
		{"cmd:deploy-*", "cmd:deploy-prod", true},
		{"cmd:deploy-*", "cmd:other", false},
		{"exact", "exact", true},
		{"exact", "exact-but-longer", false},
		{"https://api.github.com/*", "echo hi", false}, // URL scope, non-URL resource
		{"*", "https://u:p@evil.com/x", true},          // unbounded matches even uncanny resources
	}
	for _, c := range cases {
		if got := scopeMatches(c.scope, c.resource); got != c.want {
			t.Errorf("scopeMatches(%q,%q)=%v want %v", c.scope, c.resource, got, c.want)
		}
	}
}

// Property test: generated children accepted by scopeContains must
// only match resources the parent also matches.
func TestDeleg_ScopeContainment_Property(t *testing.T) {
	resources := []string{
		"https://api.github.com/", "https://api.github.com/x",
		"https://api.github.com/a/b/c", "https://api.github.com/x?q=1",
		"https://evil.example/", "https://api.github.com.evil.com/",
		"repo://org/", "repo://org/r", "repo://evil/r",
		"cmd:deploy-prod", "cmd:deploy-", "cmd:x", "echo hi",
		"https://API.GITHUB.COM/x", "https://api.github.com:443/x",
	}
	parents := []string{
		"*", "https://api.github.com/*", "repo://org/*",
		"cmd:deploy-*", "exact-thing",
	}
	children := []string{
		"*", "https://api.github.com/*", "https://api.github.com/repos/*",
		"https://api.github.com/x", "https://api.github.com",
		"repo://org/*", "repo://org/r", "repo://org/x*",
		"cmd:deploy-*", "cmd:deploy-prod", "cmd:deploy-prod-*",
		"exact-thing", "echo hi", "evil://x repo://org/",
		"https://evil.example/?u=https://api.github.com/",
	}
	for _, p := range parents {
		for _, c := range children {
			contained := scopeContains(p, c)
			for _, x := range resources {
				if scopeMatches(c, x) && !scopeMatches(p, x) && contained {
					t.Fatalf("CONTAINMENT VIOLATION: %q ⊆ %q accepted, but %q matches child not parent", c, p, x)
				}
			}
		}
	}
}

// DELEG-29/30/31: canonicalization — distinct objects → distinct bytes.
func TestDeleg_CanonicalCollisions(t *testing.T) {
	base := models.Authority{
		Issuer: "i", SubjectID: "s", Actions: []string{"a", "b"},
		ResourceScope: "r", ExpiresAt: time.Unix(100, 0), Nonce: "n",
	}
	mk := func(m func(*models.Authority)) []byte {
		a := base
		m(&a)
		return hopPayload([]models.Authority{a}, 0, "")
	}
	payloads := map[string][]byte{"base": mk(func(a *models.Authority) {})}
	variants := map[string]func(*models.Authority){
		"actions-split":  func(a *models.Authority) { a.Actions = []string{"a b"} }, // was the %v collision
		"actions-joined": func(a *models.Authority) { a.Actions = []string{"ab"} },
		"issuer-pipe":    func(a *models.Authority) { a.Issuer = "i|x"; a.SubjectID = "" },
		"subject-pipe":   func(a *models.Authority) { a.SubjectID = "s|x" },
		"empty-actions":  func(a *models.Authority) { a.Actions = nil },
		"empty-scope":    func(a *models.Authority) { a.ResourceScope = "" },
		"diff-expiry":    func(a *models.Authority) { a.ExpiresAt = time.Unix(101, 0) },
		"diff-nonce":     func(a *models.Authority) { a.Nonce = "n2" },
		"diff-audience":  func(a *models.Authority) { a.Audience = "aud" },
	}
	for name, f := range variants {
		got := mk(f)
		if string(got) == string(payloads["base"]) {
			t.Fatalf("COLLISION: variant %s produced identical signed bytes", name)
		}
		payloads[name] = got
	}
	// every variant differs from every other
	seen := map[string]string{}
	for name, p := range payloads {
		key := string(p)
		if prev, dup := seen[key]; dup {
			t.Fatalf("COLLISION: %s == %s", name, prev)
		}
		seen[key] = name
	}
}

// DELEG-32: parent linkage mutation — splice a hop from another chain.
func TestDeleg_ParentLinkageMutation(t *testing.T) {
	k := newDelegKeys(t, "root", "mid")
	v := NewValidatorWithTrustedKeys(k.pub)
	h0 := validHop("root", "mid")
	h1 := validHop("mid", "ag_abc")
	c := mintChain(k, []models.Authority{h0, h1})
	// reorder — hop linkage + signatures both fail
	c2 := &models.DelegationChain{Authorities: []models.Authority{c.Authorities[1], c.Authorities[0]}}
	if r := v.ValidateDelegationChain(c2, "ag_abc", nil); r.Valid {
		t.Fatal("reordered chain must not validate")
	}
	// splice hop0 from a different chain into this chain
	other0 := validHop("root", "mid")
	other0.Nonce = "different"
	c3 := mintChain(k, []models.Authority{other0})
	c3.Authorities = append(c3.Authorities, c.Authorities[1]) // h1 signed against original h0
	if r := v.ValidateDelegationChain(c3, "ag_abc", nil); r.Valid {
		t.Fatal("spliced chain must not validate")
	}
}

// DELEG-33 untrusted intermediate issuer.
func TestDeleg_UntrustedIntermediate(t *testing.T) {
	k := newDelegKeys(t, "root", "mid-issuer")
	v := NewValidatorWithTrustedKeys(k.pub) // both ARE trusted — but...
	// a hop signed by an issuer NOT in the registry must fail even when
	// linkage is correct. Use a third unregistered issuer.
	rogue := newDelegKeys(t, "rogue")
	h0 := validHop("root", "rogue")
	c1 := mintChain(k, []models.Authority{h0})
	h1 := validHop("rogue", "ag_abc")
	// sign h1 with rogue key but inside c1's chain for linkage
	prevSig := ""
	for i := range c1.Authorities {
		c1.Authorities[i].Signature = ed25519.Sign(k.priv[c1.Authorities[i].Issuer], hopPayload(c1.Authorities, i, prevSig))
		prevSig = hexOf(c1.Authorities[i].Signature)
	}
	c1.Authorities = append(c1.Authorities, h1)
	prev := hexOf(c1.Authorities[0].Signature)
	c1.Authorities[1].Signature = ed25519.Sign(rogue.priv["rogue"], hopPayload(c1.Authorities, 1, prev))
	if r := v.ValidateDelegationChain(c1, "ag_abc", nil); r.Valid {
		t.Fatal("chain with unregistered intermediate issuer must not validate")
	}
}

func hexOf(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = hexdig[c>>4], hexdig[c&0xf]
	}
	return string(out)
}

// DELEG-34 cross-domain (audience) — covered by AudienceExpansion.

// DELEG-35 expired chain.
func TestDeleg_ExpiredChain(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	h := validHop("root", "ag_abc")
	h.ExpiresAt = time.Now().Add(-time.Hour)
	c := mintChain(k, []models.Authority{h})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("expired chain must not validate")
	}
}

// DELEG-36 replay after restart — nonce cache is process-local:
// documented behavior, verified by construction (in-memory map).
// The guarantee: replay protection is process-local and time-bounded
// (5-min TTL), NOT persistent. Covered in the report's claim matrix.

// subject binding (terminal subject == authenticated principal)
func TestDeleg_SubjectBinding(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	c := mintChain(k, []models.Authority{validHop("root", "ag_b")})
	if r := v.ValidateDelegationChain(c, "ag_a", nil); r.Valid {
		t.Fatal("chain for another subject must not validate for this caller")
	}
	if r := v.ValidateDelegationChain(c, "ag_b", nil); !r.Valid {
		t.Fatalf("chain for the caller must validate: %v", r.Reasons)
	}
}

// missing terminal nonce → reject (replay protection mandatory).
func TestDeleg_MissingTerminalNonce(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	h := validHop("root", "ag_abc")
	h.Nonce = ""
	c := mintChain(k, []models.Authority{h})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("terminal hop without nonce must not validate")
	}
}

// narrowing is permitted (non-amplification allows subsets).
func TestDeleg_NarrowingAllowed(t *testing.T) {
	k := newDelegKeys(t, "root", "mid")
	v := NewValidatorWithTrustedKeys(k.pub)
	h0 := validHop("root", "mid")
	h0.Actions = []string{"shell", "exec"}
	h0.ResourceScope = "repo://org/*"
	h0.ExpiresAt = time.Now().Add(2 * time.Hour)
	h1 := validHop("mid", "ag_abc")
	h1.Actions = []string{"shell"}
	h1.ResourceScope = "repo://org/repo1"
	h1.ExpiresAt = time.Now().Add(time.Hour)
	c := mintChain(k, []models.Authority{h0, h1})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); !r.Valid {
		t.Fatalf("narrowing chain rejected: %v", r.Reasons)
	}
	// and the effective capability is the terminal hop's
	acts, scope := TerminalCapability(c)
	if len(acts) != 1 || acts[0] != "shell" || scope != "repo://org/repo1" {
		t.Fatalf("terminal capability wrong: %v %q", acts, scope)
	}
}

// malformed scope in a hop → rejected (not just non-containing).
func TestDeleg_InvalidScopeRejected(t *testing.T) {
	k := newDelegKeys(t, "root")
	v := NewValidatorWithTrustedKeys(k.pub)
	h := validHop("root", "ag_abc")
	h.ResourceScope = "evil://x repo://org/"
	c := mintChain(k, []models.Authority{h})
	if r := v.ValidateDelegationChain(c, "ag_abc", nil); r.Valid {
		t.Fatal("malformed scope must not validate")
	}
}

// Replay-poisoning: a forged/invalid chain presenting a victim's nonce
// must NOT consume the nonce — the mark happens only after full
// cryptographic validation.
func TestDeleg_ReplayPoisoning(t *testing.T) {
	k := newDelegKeys(t, "root")
	evil := newDelegKeys(t, "root") // same issuer id, wrong key
	v := NewValidatorWithTrustedKeys(k.pub)
	seen := map[string]bool{}
	seenFn := func(n string, _ time.Time) NonceMark {
		if seen[n] {
			return NonceMarkSeen
		}
		seen[n] = true
		return NonceMarkFirst
	}

	// Attacker submits a FORGED chain (bad signature) claiming nonce "victim-n".
	forged := mintChain(evil, []models.Authority{validHop("root", "ag_v")})
	forged.Authorities[0].Nonce = "victim-n"
	if r := v.ValidateDelegationChain(forged, "ag_v", seenFn); r.Valid {
		t.Fatal("forged chain must not validate")
	}
	// The victim's legitimate chain with that nonce must still be accepted —
	// the forged presentation must not have consumed the nonce.
	legit := mintChain(k, []models.Authority{validHop("root", "ag_v")})
	legit.Authorities[0].Nonce = "victim-n"
	signHops(legit, k.priv)
	if r := v.ValidateDelegationChain(legit, "ag_v", seenFn); !r.Valid {
		t.Fatalf("legit chain poisoned by forged replay: %v", r.Reasons)
	}
	// And the second legit presentation is the replay that's denied.
	if r := v.ValidateDelegationChain(legit, "ag_v", seenFn); r.Valid {
		t.Fatal("second presentation must be denied as replay")
	}
}

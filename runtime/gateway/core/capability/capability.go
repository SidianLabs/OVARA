// Package capability implements v2's attenuable capability tokens
// (spec/capability_token.md). Choice: stdlib-Ed25519 signed envelope
// with explicit attenuation blocks — no external token library, so
// the TCB stays dependency-free (biscuit-go adapter can be added as
// a backend later without changing semantics; deviation recorded in
// DECISIONS.md).
package capability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"ovara.runtime.gateway/core/action"
)

// Scope bounds what a token authorizes. All fields conjunctive.
type Scope struct {
	ActionTypes []string `json:"action_types"` // closed enum values; empty = none
	Resources   []string `json:"resources"`    // canonical patterns, * suffix = prefix
	Envs        []string `json:"envs"`         // allowed environments; empty = none
	RatePerMin  int      `json:"rate_per_min,omitempty"`
}

// Caveat narrows a token. Kind decides semantics.
type Caveat struct {
	Kind  string `json:"kind"` // "expires_before" | "env_in" | "taint_max"
	Value string `json:"value"`
}

// Block is one authority layer. Block 0 = authority (issued by a
// trusted issuer); each appended block can only narrow scope/expiry —
// attenuation-only is enforced at Verify (P4).
type Block struct {
	Scope   Scope    `json:"scope"`
	Caveats []Caveat `json:"caveats,omitempty"`
	// Issuer is the pubID of the key that signed this block; Subject
	// is the pubID of the key that may PRESENT the token from this
	// block onward. Block 0's issuer is a trusted issuer and its
	// subject is the token's holder; an attenuation's issuer is the
	// previous block's subject (chain of custody — only the holder
	// may delegate), and its subject is the delegatee.
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Delegate bool   `json:"delegate"` // whether holder may append further blocks
}

// Token is a chain of blocks; signature covers everything before it.
type Token struct {
	ID     string    `json:"id"`
	Issued time.Time `json:"issued"`
	Epoch  uint64    `json:"epoch"`
	Blocks []Block   `json:"blocks"`
	// Sigs[i] signs canonical(blocks[0..i]) chained with Sigs[i-1].
	Sigs []string `json:"sigs"`
}

func blockCanonical(b Block) string {
	j, _ := json.Marshal(b)
	sum := sha256.Sum256(j)
	return hex.EncodeToString(sum[:])
}

func tokenCanonical(t *Token, upto int) string {
	var parts []string
	for i := 0; i <= upto; i++ {
		parts = append(parts, blockCanonical(t.Blocks[i]))
	}
	prev := "genesis"
	if upto > 0 {
		prev = t.Sigs[upto-1]
	}
	return fmt.Sprintf("cap|%s|%d|%d|%s|%s", t.ID, t.Issued.UnixNano(),
		t.Epoch, strings.Join(parts, "."), prev)
}

// Issue mints a block-0 token signed by issuer, bound to subject
// (the holder's pubkey id — only that key's actor may present it).
func Issue(issuer ed25519.PrivateKey, id string, epoch uint64, subject ed25519.PublicKey, s Scope, cav []Caveat, delegate bool) (*Token, error) {
	if len(s.ActionTypes) == 0 || len(s.Resources) == 0 || len(s.Envs) == 0 {
		return nil, errors.New("capability: block-0 scope must be fully populated (empty = none is too surprising)")
	}
	for _, ty := range s.ActionTypes {
		if !action.Type(ty).Valid() {
			return nil, fmt.Errorf("capability: unknown action type %q in scope", ty)
		}
	}
	t := &Token{ID: id, Issued: time.Now().UTC(), Epoch: epoch,
		Blocks: []Block{{Scope: s, Caveats: cav,
			Issuer:   pubID(issuer.Public().(ed25519.PublicKey)),
			Subject:  pubID(subject),
			Delegate: delegate}}}
	t.Sigs = []string{sign(issuer, tokenCanonical(t, 0))}
	return t, nil
}

// Attenuate appends a narrowing block signed by the delegating key,
// handing the token to subject (the delegatee's pubkey). The
// delegator must BE the current tail subject — only the holder of
// record may delegate (chain of custody). Structural P4 subset
// enforcement happens at Verify.
func Attenuate(t *Token, delegator ed25519.PrivateKey, subject ed25519.PublicKey, s Scope, cav []Caveat, delegate bool) (*Token, error) {
	if len(t.Blocks) == 0 {
		return nil, errors.New("capability: empty token")
	}
	last := t.Blocks[len(t.Blocks)-1]
	if pubID(delegator.Public().(ed25519.PublicKey)) != last.Subject {
		return nil, errors.New("capability: delegator is not the token holder (chain-of-custody violation)")
	}
	if !last.Delegate {
		return nil, errors.New("capability: terminal block — cannot delegate (P5)")
	}
	eff := effectiveScope(t.Blocks)
	if !subsetOf(s, eff) {
		return nil, errors.New("capability: attenuation must narrow scope (P4)")
	}
	// expiry monotone: new expires_before caveat can't exceed existing
	if !expiryMonotone(cav, last.Caveats) {
		return nil, errors.New("capability: expiry cannot widen (P4)")
	}
	nt := *t
	nb := Block{Scope: s, Caveats: cav,
		Issuer:   pubID(delegator.Public().(ed25519.PublicKey)),
		Subject:  pubID(subject),
		Delegate: delegate}
	nt.Blocks = append(append([]Block{}, t.Blocks...), nb)
	nt.Sigs = append(append([]string{}, t.Sigs...),
		sign(delegator, tokenCanonical(&nt, len(nt.Blocks)-1)))
	return &nt, nil
}

// Verify checks signatures end-to-end and returns the effective scope.
// epoch must be ≥ token.Epoch (revocation dominance hook — caller
// also checks min_epoch on the action).
// signers covers every key trusted to sign a block: issuer keys AND
// holder keys (delegation blocks are signed by the previous subject).
// Callers pass ActorKeys-by-pubID alongside issuer keys.
func Verify(t *Token, signers map[string]ed25519.PublicKey, currentEpoch uint64) (Scope, error) {
	if len(t.Blocks) == 0 || len(t.Sigs) != len(t.Blocks) {
		return Scope{}, errors.New("capability: malformed token")
	}
	if t.Epoch < currentEpoch {
		return Scope{}, errors.New("capability: token epoch stale (revoked)")
	}
	for i, b := range t.Blocks {
		pub, ok := signers[b.Issuer]
		if !ok {
			return Scope{}, fmt.Errorf("capability: untrusted issuer %q at block %d", b.Issuer, i)
		}
		if !checkSig(pub, tokenCanonical(t, i), t.Sigs[i]) {
			return Scope{}, fmt.Errorf("capability: bad signature at block %d", i)
		}
		if i > 0 {
			if !t.Blocks[i-1].Delegate {
				return Scope{}, errors.New("capability: delegation beyond terminal block")
			}
			if b.Issuer != t.Blocks[i-1].Subject {
				return Scope{}, fmt.Errorf("capability: block %d signed by non-holder (custody violation)", i)
			}
			eff := effectiveScope(t.Blocks[:i])
			if !subsetOf(b.Scope, eff) {
				return Scope{}, fmt.Errorf("capability: block %d widens scope (P4 violation)", i)
			}
		}
	}
	eff := effectiveScope(t.Blocks)
	if err := checkCaveats(t.Blocks); err != nil {
		return Scope{}, err
	}
	return eff, nil
}

// Covers reports whether the effective scope permits the action.
func (s Scope) Covers(a action.Action) bool {
	typeOK := false
	for _, ty := range s.ActionTypes {
		if ty == "*" || ty == string(a.Type) {
			typeOK = true
		}
	}
	if !typeOK {
		return false
	}
	resOK := false
	for _, p := range s.Resources {
		if p == "*" || p == a.Resource ||
			(strings.HasSuffix(p, "*") && strings.HasPrefix(a.Resource, strings.TrimSuffix(p, "*"))) {
			resOK = true
		}
	}
	if !resOK {
		return false
	}
	envOK := false
	for _, e := range s.Envs {
		if e == "*" || e == string(a.Env) {
			envOK = true
		}
	}
	return envOK
}

func effectiveScope(blocks []Block) Scope {
	// Intersection of all block scopes, each narrowed by its own
	// env_in caveat (RT-R2: env binding must be enforced, not just
	// declared).
	eff := caveatNarrow(blocks[0])
	for _, b := range blocks[1:] {
		eff = intersect(eff, caveatNarrow(b))
	}
	return eff
}

// caveatNarrow applies env_in to the block's env grant.
func caveatNarrow(b Block) Scope {
	s := b.Scope
	for _, c := range b.Caveats {
		if c.Kind == "env_in" && c.Value != "" {
			s.Envs = intersectSet(s.Envs, strings.Split(c.Value, ","))
		}
	}
	return s
}

func intersect(a, b Scope) Scope {
	return Scope{
		ActionTypes: intersectSet(a.ActionTypes, b.ActionTypes),
		Resources:   intersectPattern(a.Resources, b.Resources),
		Envs:        intersectSet(a.Envs, b.Envs),
		RatePerMin:  minNZ(a.RatePerMin, b.RatePerMin),
	}
}

func intersectSet(a, b []string) []string {
	if has(a, "*") {
		return b
	}
	if has(b, "*") {
		return a
	}
	var out []string
	for _, x := range a {
		if has(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// intersectPattern: prefix patterns intersect if one is a prefix of
// the other, or both list the same literal.
func intersectPattern(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			switch {
			case x == "*" || y == "*":
				out = append(out, x) // * absorbs: keep narrower below
				if x == "*" {
					out[len(out)-1] = y
				}
			case x == y:
				out = append(out, x)
			case strings.HasSuffix(x, "*") && strings.HasPrefix(y, strings.TrimSuffix(x, "*")):
				out = append(out, y) // y narrower
			case strings.HasSuffix(y, "*") && strings.HasPrefix(x, strings.TrimSuffix(y, "*")):
				out = append(out, x)
			}
		}
	}
	return out
}

func subsetOf(inner, outer Scope) bool {
	if !has(outer.ActionTypes, "*") {
		for _, ty := range inner.ActionTypes {
			if !has(outer.ActionTypes, ty) {
				return false
			}
		}
	}
	if !has(outer.Resources, "*") {
		for _, r := range inner.Resources {
			ok := false
			for _, o := range outer.Resources {
				if o == r || (strings.HasSuffix(o, "*") &&
					strings.HasPrefix(r, strings.TrimSuffix(o, "*"))) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
	}
	if !has(outer.Envs, "*") {
		for _, e := range inner.Envs {
			if !has(outer.Envs, e) {
				return false
			}
		}
	}
	if outer.RatePerMin > 0 && (inner.RatePerMin == 0 || inner.RatePerMin > outer.RatePerMin) {
		return false
	}
	return true
}

func checkCaveats(blocks []Block) error {
	now := time.Now().UTC()
	for _, b := range blocks {
		for _, c := range b.Caveats {
			switch c.Kind {
			case "expires_before":
				exp, err := time.Parse(time.RFC3339, c.Value)
				if err != nil {
					return fmt.Errorf("capability: bad expiry caveat %q", c.Value)
				}
				if now.After(exp) {
					return errors.New("capability: expired")
				}
			case "env_in": // enforced in effectiveScope via caveatNarrow
			default:
				// A caveat the verifier can't enforce must fail
				// closed — silent acceptance is how capability
				// restrictions get bypassed (e.g. taint_max is
				// reserved but not yet implemented).
				return fmt.Errorf("capability: unenforced caveat kind %q", c.Kind)
			}
		}
	}
	return nil
}

func expiryMonotone(newCav, existing []Caveat) bool {
	var newest time.Time
	for _, c := range newCav {
		if c.Kind == "expires_before" {
			t, err := time.Parse(time.RFC3339, c.Value)
			if err == nil && (newest.IsZero() || t.Before(newest)) {
				newest = t
			}
		}
	}
	if newest.IsZero() {
		// no expiry in new block — only OK if outer has none either
		for _, c := range existing {
			if c.Kind == "expires_before" {
				return false
			}
		}
		return true
	}
	for _, c := range existing {
		if c.Kind == "expires_before" {
			t, _ := time.Parse(time.RFC3339, c.Value)
			if !t.IsZero() && newest.After(t) {
				return false
			}
		}
	}
	return true
}

func has(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func minNZ(a, b int) int {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func sign(k ed25519.PrivateKey, payload string) string {
	return "edsig_v2:" + hex.EncodeToString(ed25519.Sign(k, []byte(payload)))
}

func checkSig(pub ed25519.PublicKey, payload, sig string) bool {
	if !strings.HasPrefix(sig, "edsig_v2:") {
		return false
	}
	b, err := hex.DecodeString(sig[9:])
	return err == nil && ed25519.Verify(pub, []byte(payload), b)
}

func pubID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "cap_" + hex.EncodeToString(sum[:8])
}

// PubID is exported for issuers registration.
func PubID(pub ed25519.PublicKey) string { return pubID(pub) }

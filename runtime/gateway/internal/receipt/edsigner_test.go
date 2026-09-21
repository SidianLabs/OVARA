package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
)

func testRegistry(t *testing.T) (*gwidentity.Registry, ed25519.PrivateKey, string, string) {
	t.Helper()
	reg := gwidentity.NewInMemory()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := reg.Register("gw-A", pub)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg, priv, "gw-A", rec.KeyID
}

func sampleReceipt() *models.Receipt {
	return &models.Receipt{
		ReceiptID:         "rcpt_1",
		DecisionID:        "dec_1",
		ActionDigest:      "sha256:abcd",
		ActionType:        "shell",
		Resource:          "host",
		AgentID:           "ag_x",
		CapabilityLeaseID: "lse_1",
		Decision:          "allow",
		PolicyVersion:     "v1",
		TrustScore:        0.75,
		TrustLevel:        models.TrustLevelHigh,
		AnomalySignals:    []models.AnomalySignal{{Code: "burst", Pattern: "p", Severity: "low"}},
		ShieldActive:      true,
		RiskCount:         2,
		ApprovalID:        "ap_1",
		ApprovalDecision:  "approved",
		TrustEpoch:        7,
		IssuedAt:          time.Unix(1700000000, 123456789).UTC(),
		Signature:         "sig_v1:deadbeef",
	}
}

func resolver(reg *gwidentity.Registry) KeyResolver {
	return RegistryResolver{Reg: reg}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	if !strings.HasPrefix(r.GatewaySig, "edsig_v1:") {
		t.Fatalf("sig prefix: %q", r.GatewaySig)
	}
	ok, err := VerifySignature(resolver(reg), r)
	if err != nil || !ok {
		t.Fatalf("valid receipt rejected: ok=%v err=%v", ok, err)
	}
}

// RS-04: tampering with ANY signed field invalidates the signature.
func TestTamper_EverySignedField(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	signer := NewEdSigner(priv, gw, kid)

	cases := map[string]func(*models.Receipt){
		"receipt_id":    func(r *models.Receipt) { r.ReceiptID = "rcpt_X" },
		"decision_id":   func(r *models.Receipt) { r.DecisionID = "dec_X" },
		"action_digest": func(r *models.Receipt) { r.ActionDigest = "sha256:0000" },
		"action_type":   func(r *models.Receipt) { r.ActionType = "git.push" },
		"resource":      func(r *models.Receipt) { r.Resource = "prod-db" },
		"agent_id":      func(r *models.Receipt) { r.AgentID = "ag_evil" },
		"lease_id":      func(r *models.Receipt) { r.CapabilityLeaseID = "lse_X" },
		"decision":      func(r *models.Receipt) { r.Decision = "deny" },
		"policy":        func(r *models.Receipt) { r.PolicyVersion = "v99" },
		"trust_score":   func(r *models.Receipt) { r.TrustScore = 1.0 },
		"trust_level":   func(r *models.Receipt) { r.TrustLevel = models.TrustLevelLow },
		"anomalies":     func(r *models.Receipt) { r.AnomalySignals[0].Code = "none" },
		"anomaly_count": func(r *models.Receipt) { r.AnomalySignals = nil },
		"shield":        func(r *models.Receipt) { r.ShieldActive = false },
		"restricted":    func(r *models.Receipt) { r.Restricted = true },
		"risk_count":    func(r *models.Receipt) { r.RiskCount = 0 },
		"approval_id":   func(r *models.Receipt) { r.ApprovalID = "ap_X" },
		"approval_dec":  func(r *models.Receipt) { r.ApprovalDecision = "denied" },
		"trust_epoch":   func(r *models.Receipt) { r.TrustEpoch = 999 },
		"issued_at":     func(r *models.Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Hour) },
		// Gate findings G1/G2 — nanosecond drift and HMAC-field
		// tampering must both invalidate.
		"issued_at_nanos": func(r *models.Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Nanosecond) },
		"hmac_field":      func(r *models.Receipt) { r.Signature = "sig_v1:forged" },
		"hmac_stripped":   func(r *models.Receipt) { r.Signature = "" },
		"gateway_id":      func(r *models.Receipt) { r.GatewayID = "gw_Z" },
		"gateway_key_id":  func(r *models.Receipt) { r.GatewayKeyID = "gwk_Z" },
	}
	for name, mutate := range cases {
		r := sampleReceipt()
		signer.SignReceipt(r)
		mutate(r)
		ok, err := VerifySignature(resolver(reg), r)
		// Not-valid is the invariant — cryptographic mismatch
		// (false,nil) or unresolvable identity (false,err) both reject.
		if ok {
			t.Fatalf("%s: tampered receipt verified (ok=%v err=%v)", name, ok, err)
		}
	}
}

// RS-05: gateway_id / key_id substitution cannot produce a valid
// signature — ids are covered by the signature AND resolved via the
// registry, so swapping either breaks resolution or verification.
func TestCrossGatewaySubstitution(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	// Register a second gateway so gw-B exists in the registry.
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := reg.Register("gw-B", pubB); err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)

	r.GatewayID = "gw-B" // gw-B exists but never held key_id → resolution fails
	ok, err := VerifySignature(resolver(reg), r)
	if ok {
		t.Fatalf("cross-gateway substitution verified")
	}
	if err == nil {
		t.Fatalf("expected resolution error for wrong gateway, got nil")
	}

	r = sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	r.GatewayID = "gw-C" // unknown gateway → resolution error
	ok, err = VerifySignature(resolver(reg), r)
	if ok || err == nil {
		t.Fatalf("unknown gateway should error: ok=%v err=%v", ok, err)
	}
}

func TestKeyIDSubstitution(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	rec2, err := reg.Rotate(gw, pub2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	r.GatewayKeyID = rec2.KeyID // claims rotation's key, signed by old
	ok, err := VerifySignature(resolver(reg), r)
	if ok || err != nil {
		t.Fatalf("key_id substitution verified: ok=%v err=%v", ok, err)
	}
}

// Key substitution attack: attacker signs with their own key but
// claims the victim's (gateway_id, key_id). The registry never lets
// a caller choose key_id (newKeyID assigns), so the attacker's key
// lands under a different id — the claimed id resolves to the
// VICTIM's key and the attacker signature fails.
func TestAttackerSignatureClaimingVictimKeyID(t *testing.T) {
	reg, _, gw, kid := testRegistry(t)
	apub, apriv, _ := ed25519.GenerateKey(rand.Reader)
	arec, err := reg.Register("gw-attacker", apub)
	if err != nil {
		t.Fatal(err)
	}
	if arec.KeyID == kid {
		t.Fatal("key_id collision — registry ids must be unique")
	}
	r := sampleReceipt()
	// Attacker signs with apriv but stamps the victim identity.
	NewEdSigner(apriv, gw, kid).SignReceipt(r)
	ok, err := VerifySignature(resolver(reg), r)
	if ok || err != nil {
		t.Fatalf("attacker-signed receipt claiming victim key verified: ok=%v err=%v", ok, err)
	}
}

// RS-06: domain separation — a PoP signature can never verify as a
// receipt signature and vice versa.
func TestDomainSeparation_PoPNotReceipt(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	challenge, _ := gwidentity.Challenge()
	popSig := gwidentity.Prove(priv, gw, kid, challenge)

	r := sampleReceipt()
	r.GatewayID, r.GatewayKeyID = gw, kid
	r.GatewaySig = "edsig_v1:" + hex.EncodeToString(popSig)
	ok, _ := VerifySignature(resolver(reg), r)
	if ok {
		t.Fatal("PoP signature accepted as receipt signature")
	}

	// And the converse: a receipt signature must not authenticate as PoP.
	r2 := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r2)
	raw, _ := hex.DecodeString(r2.GatewaySig[len("edsig_v1:"):])
	if _, err := reg.AuthenticatePeer(gw, kid, challenge, raw); err == nil {
		t.Fatal("receipt signature accepted as PoP proof")
	}
}

// RS-07: rotation — receipts signed by K1 and K2 both verify against
// the historical registry.
func TestRotation_HistoricalAndCurrentVerify(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r1 := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r1)

	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rec2, err := reg.Rotate(gw, pub2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r2 := sampleReceipt()
	r2.ReceiptID = "rcpt_2"
	NewEdSigner(priv2, gw, rec2.KeyID).SignReceipt(r2)

	for i, r := range []*models.Receipt{r1, r2} {
		ok, err := VerifySignature(resolver(reg), r)
		if !ok || err != nil {
			t.Fatalf("receipt %d failed post-rotation: ok=%v err=%v", i, ok, err)
		}
	}
	// Tampered historical receipt still fails after rotation.
	r1.Resource = "tampered"
	ok, _ := VerifySignature(resolver(reg), r1)
	if ok {
		t.Fatal("tampered historical receipt verified after rotation")
	}
}

// RS-08: a revoked key's receipts remain cryptographically verifiable
// while live authentication with that key is denied — historical
// verification ≠ current authorization.
func TestRevokedKey_HistoricalValidLiveDenied(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)

	// Rotate in a successor, then revoke the signing key.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := reg.Rotate(gw, pub2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := reg.RevokeKey(gw, kid); err != nil {
		t.Fatal(err)
	}

	ok, err := VerifySignature(resolver(reg), r)
	if !ok || err != nil {
		t.Fatalf("historical receipt under revoked key must still verify: ok=%v err=%v", ok, err)
	}
	challenge, _ := gwidentity.Challenge()
	sig := gwidentity.Prove(priv, gw, kid, challenge)
	if _, err := reg.AuthenticatePeer(gw, kid, challenge, sig); err == nil {
		t.Fatal("revoked key authenticated live — must be denied")
	}
}

func TestUnregisteredKey_Invalid(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	r.GatewayKeyID = "gwk_unregistered"
	ok, err := VerifySignature(resolver(reg), r)
	if ok || err == nil {
		t.Fatalf("unregistered key_id must fail resolution: ok=%v err=%v", ok, err)
	}
}

func TestMalformedAndTruncatedSig(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)

	for _, bad := range []string{
		"edsig_v1:zz",                          // bad hex
		"edsig_v1:" + strings.Repeat("00", 10), // truncated
		"edsig_v1:",                            // empty
		"",                                     // absent
		"sig_v1:abcd",                          // wrong scheme
	} {
		cp := *r
		cp.GatewaySig = bad
		ok, _ := VerifySignature(resolver(reg), &cp)
		if ok {
			t.Fatalf("malformed sig %q verified", bad)
		}
	}
}

// No registry → no verification. Fail closed, never a false valid.
func TestNoResolver_FailsClosed(t *testing.T) {
	_, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	ok, err := VerifySignature(nil, r)
	if ok || err == nil {
		t.Fatalf("nil resolver must not verify: ok=%v err=%v", ok, err)
	}
	ok, err = VerifySignature(RegistryResolver{}, r)
	if ok || err == nil {
		t.Fatalf("nil registry must not verify: ok=%v err=%v", ok, err)
	}
}

// RS-10: the private key never appears in the serialized receipt.
func TestReceiptJSON_NeverCarriesPrivateKey(t *testing.T) {
	_, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	blob, _ := json.Marshal(r)
	privHex := hex.EncodeToString(priv)
	privBytes := string(priv)
	if strings.Contains(string(blob), privHex) || strings.Contains(string(blob), privBytes) {
		t.Fatal("private key material leaked into receipt JSON")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if strings.Contains(string(blob), hex.EncodeToString(pub)) {
		t.Fatal("even the public key is absent — resolution is registry-side")
	}
}

// Concurrency: signing and verifying during rotation — every signed
// receipt must verify against the registry's historical record.
func TestConcurrentSignVerifyDuringRotation(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	res := resolver(reg)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := sampleReceipt()
			NewEdSigner(priv, gw, kid).SignReceipt(r)
			ok, err := VerifySignature(res, r)
			if !ok || err != nil {
				t.Errorf("concurrent verify failed: ok=%v err=%v", ok, err)
			}
		}(i)
	}
	// Rotate mid-flight — receipts signed by K1 must remain valid.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rec2, err := reg.Rotate(gw, pub2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := sampleReceipt()
			NewEdSigner(priv2, gw, rec2.KeyID).SignReceipt(r)
			ok, err := VerifySignature(res, r)
			if !ok || err != nil {
				t.Errorf("post-rotation verify failed: ok=%v err=%v", ok, err)
			}
		}()
	}
	wg.Wait()
}

// DESTROYED retains the public key record (tombstone keeps bytes) —
// historical receipts remain cryptographically verifiable; live auth
// stays denied. This is the ratified lifecycle semantic, pinned here.
func TestDestroyedKey_HistoricalStillVerifiable(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	if err := reg.Destroy(gw); err != nil {
		t.Fatal(err)
	}
	ok, err := VerifySignature(resolver(reg), r)
	if !ok || err != nil {
		t.Fatalf("destroyed-key receipt should still verify (pubkey retained): ok=%v err=%v", ok, err)
	}
	challenge, _ := gwidentity.Challenge()
	sig := gwidentity.Prove(priv, gw, kid, challenge)
	if _, err := reg.AuthenticatePeer(gw, kid, challenge, sig); err == nil {
		t.Fatal("destroyed key authenticated live — must be denied")
	}
}

// lp() framing makes field-boundary ambiguity impossible: "AB"+"C"
// can never collide with "A"+"BC". Prove payloads differ across
// split points.
func TestCanonicalPayload_NoFieldBoundaryCollision(t *testing.T) {
	pairs := [][2]func(*models.Receipt){
		{func(r *models.Receipt) { r.ReceiptID, r.DecisionID = "AB", "C" },
			func(r *models.Receipt) { r.ReceiptID, r.DecisionID = "A", "BC" }},
		{func(r *models.Receipt) { r.ActionType, r.Resource = "x:", "y" },
			func(r *models.Receipt) { r.ActionType, r.Resource = "x", ":y" }},
		{func(r *models.Receipt) { r.AgentID, r.CapabilityLeaseID = "ab", "" },
			func(r *models.Receipt) { r.AgentID, r.CapabilityLeaseID = "a", "b" }},
	}
	for i, p := range pairs {
		a, b := sampleReceipt(), sampleReceipt()
		p[0](a)
		p[1](b)
		if string(SignedPayload(a)) == string(SignedPayload(b)) {
			t.Fatalf("pair %d: field-boundary collision in payload", i)
		}
	}
	// Empty vs absent must not shift boundaries either.
	a, b := sampleReceipt(), sampleReceipt()
	a.ApprovalID = ""
	b.ApprovalID = "X"
	if string(SignedPayload(a)) == string(SignedPayload(b)) {
		t.Fatal("empty vs non-empty field produced identical payload")
	}
}

// A receipt is only verifiable inside its own trust domain: another
// domain's registry must not resolve the signature.
func TestCrossDomain_RegistryCannotVerify(t *testing.T) {
	_, priv, gw, kid := testRegistry(t)
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)

	// A second, independent registry (other trust domain).
	regB := gwidentity.NewInMemory()
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	regB.Register("gw-B", pubB)
	ok, err := VerifySignature(resolver(regB), r)
	if ok || err == nil {
		t.Fatalf("foreign-domain registry must not verify: ok=%v err=%v", ok, err)
	}
	// Same gateway_id in a different domain with a different key →
	// resolution fails or signature mismatches — never valid.
	pubC, _, _ := ed25519.GenerateKey(rand.Reader)
	regB.Register(gw, pubC)
	ok, err = VerifySignature(resolver(regB), r)
	if ok {
		t.Fatalf("same-id different-key registry verified a foreign receipt")
	}
	_ = err
}

// Unknown/future signature versions fail closed — never reinterpreted.
func TestUnknownSignatureVersion(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	_ = reg
	r := sampleReceipt()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	for _, bad := range []string{
		"edsig_v2:" + r.GatewaySig[len("edsig_v1:"):],          // future version
		"edsig_v1:edsig_v1:" + r.GatewaySig[len("edsig_v1:"):], // dup prefix
		" edsig_v1:" + r.GatewaySig[len("edsig_v1:"):],         // leading space
		"edsig_v1: " + r.GatewaySig[len("edsig_v1:"):],         // inner space
		strings.ToUpper(r.GatewaySig[:9]) + r.GatewaySig[9:],   // case-swapped prefix
	} {
		cp := *r
		cp.GatewaySig = bad
		ok, _ := VerifySignature(resolver(reg), &cp)
		if ok {
			t.Fatalf("version/prefix variant %q verified", bad[:20])
		}
	}
}

// Crash safety: receipt signed before restart verifies against the
// durable registry after reopen — the key record outlives the process.
func TestCrashSafety_RegistryPersists(t *testing.T) {
	path := t.TempDir() + "/reg.jsonl"
	reg, err := gwidentity.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec, err := reg.Register("gw-A", pub)
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	NewEdSigner(priv, "gw-A", rec.KeyID).SignReceipt(r)
	reg.Close()

	reg2, err := gwidentity.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	ok, err := VerifySignature(RegistryResolver{Reg: reg2}, r)
	if !ok || err != nil {
		t.Fatalf("receipt unverifiable after restart: ok=%v err=%v", ok, err)
	}
}

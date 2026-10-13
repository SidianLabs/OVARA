package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The SDK verifiers (sdk/python, sdk/typescript) check proxy receipts
// without this package, so they are tested against vectors this package
// produces: sdk/testdata/receipts_v2.json. TestSDKVectors rebuilds the
// vectors and fails if the committed file differs, so the file cannot
// drift from what the proxy writes. Regenerate it with
//
//	OVARA_WRITE_SDK_VECTORS=1 go test ./internal/receipts -run TestSDKVectors
//
// Ed25519 signatures are deterministic, so the same seed and inputs give
// the same file byte for byte.

const sdkVectorsPath = "../../../sdk/testdata/receipts_v2.json"

type sdkVector struct {
	Name string `json:"name"`
	// Valid is what Go's verifier says about Line on its own, under the
	// file's public key.
	Valid bool   `json:"valid"`
	Why   string `json:"why"`
	// Line is the exact receipt line as it appears in a chain file.
	Line string `json:"line"`
	// Version is the canonical form a verifier must pick for the receipt
	// (1 or 2); CanonicalHex is that payload and Digest its SHA-256.
	Version      int    `json:"version"`
	CanonicalHex string `json:"canonical_hex"`
	Digest       string `json:"digest"`
}

type sdkVectorFile struct {
	Comment   string      `json:"comment"`
	PublicKey string      `json:"public_key"`
	KeyID     string      `json:"key_id"`
	Vectors   []sdkVector `json:"vectors"`
}

func vectorKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func signV1(key ed25519.PrivateKey, r *Receipt) {
	r.Signature = sigV1Prefix + hex.EncodeToString(ed25519.Sign(key, []byte(r.canonicalV1())))
}

func signV2(key ed25519.PrivateKey, r *Receipt) {
	r.Signature = sigV2Prefix + hex.EncodeToString(ed25519.Sign(key, r.canonicalV2()))
}

func mustLine(t *testing.T, r *Receipt) []byte {
	t.Helper()
	line, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// sdkVersion is the rule the SDKs use to pick a canonical form: v2 when the
// receipt says v2 in any way (the version field, the signature prefix, or
// any field only v2 signs), v1 otherwise.
func sdkVersion(r *Receipt) int {
	if r.V == 2 || strings.HasPrefix(r.Signature, sigV2Prefix) || r.hasV2Fields() {
		return 2
	}
	return 1
}

func buildSDKVectors(t *testing.T) (*sdkVectorFile, [][]byte) {
	t.Helper()
	key := vectorKey(0x42)
	other := vectorKey(0x43)
	pub := key.Public().(ed25519.PublicKey)
	kid := KeyID(pub)

	var vecs []sdkVector
	add := func(name string, valid bool, why string, line []byte) {
		r, err := parseLine(line)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var payload []byte
		ver := sdkVersion(r)
		if ver == 2 {
			payload = r.canonicalV2()
		} else {
			payload = []byte(r.canonicalV1())
		}
		sum := sha256.Sum256(payload)
		vecs = append(vecs, sdkVector{Name: name, Valid: valid, Why: why, Line: string(line),
			Version: ver, CanonicalHex: hex.EncodeToString(payload), Digest: hex.EncodeToString(sum[:])})
	}

	// A valid chain: v1, v1 with approval, v2 attempt, v2 outcome, v2 deny.
	var chain [][]byte

	v1 := &Receipt{ReceiptID: "rcpt_00000000000000a1", SessionID: "sess_v1", Timestamp: mustTime(t, "2026-01-02T03:04:05.123456789Z"),
		Method: "GET", URL: "https://api.example.com/a|b?q=1", Decision: "allow", Status: 200}
	signV1(key, v1)
	l := mustLine(t, v1)
	add("v1_allow", true, "legacy receipt: no v, sig_v1 over the pipe-joined payload", l)
	chain = append(chain, l)

	v1a := &Receipt{ReceiptID: "rcpt_00000000000000a2", SessionID: "sess_v1", Timestamp: mustTime(t, "2026-01-02T03:04:06Z"),
		Method: "POST", URL: "https://api.example.com/upload", Decision: "allow", Status: 201, ApprovalID: "apr_123", PrevHash: hashLine(l)}
	signV1(key, v1a)
	l = mustLine(t, v1a)
	add("v1_with_approval", true, "legacy receipt with approval_id appended to the payload", l)
	chain = append(chain, l)

	attempt := &Receipt{V: 2, ReceiptID: "rcpt_00000000000000b1", SessionID: "sess_v2", Timestamp: mustTime(t, "2026-01-02T03:04:07.5Z"),
		Method: "POST", URL: "https://api.example.com/v1/messages", Decision: "allow",
		Phase: "attempt", Outcome: "sent", Agent: "pt_0123456789abcdef", Rule: "allow api posts",
		PolicyHash: "sha256:feedface", ReqBytes: 1234, BodySHA256: strings.Repeat("ab", 32),
		Reasons: []string{"policy_allow"}, KeyID: kid, PrevHash: hashLine(l)}
	signV2(key, attempt)
	l = mustLine(t, attempt)
	add("v2_attempt", true, "v2 attempt receipt written before the request goes upstream", l)
	chain = append(chain, l)

	outcome := &Receipt{V: 2, ReceiptID: "rcpt_00000000000000b2", SessionID: "sess_v2", Timestamp: mustTime(t, "2026-01-02T08:34:07.000000001+05:30"),
		Method: "POST", URL: "https://api.example.com/v1/messages", Decision: "escalate", Status: 200, ApprovalID: "apr_é",
		Phase: "outcome", AttemptID: attempt.ReceiptID, Agent: "pt_0123456789abcdef", Rule: "règle «approve» 規則",
		PolicyHash: "sha256:feedface", Approver: "José Ñúñez <ops@example.com>", ReqBytes: 1234, RespBytes: -1,
		Reasons: []string{"needs_approval", "", "approved by 担当者 ✅ 🔑", "a|b"}, KeyID: kid, PrevHash: hashLine(l)}
	signV2(key, outcome)
	l = mustLine(t, outcome)
	add("v2_outcome_reasons_approver", true, "v2 outcome with unicode, an empty reason, a non-UTC offset and resp_bytes -1", l)
	chain = append(chain, l)
	outcomeLine := l

	deny := &Receipt{V: 2, ReceiptID: "rcpt_00000000000000b3", SessionID: "sess_v2", Timestamp: mustTime(t, "2026-01-02T03:04:09Z"),
		Method: "", URL: "", Decision: "deny", KeyID: kid, PrevHash: hashLine(l)}
	signV2(key, deny)
	l = mustLine(t, deny)
	add("v2_deny_empty_fields", true, "v2 receipt whose optional fields, method and url are all empty", l)
	chain = append(chain, l)

	// Invalid vectors.
	tampered := strings.Replace(string(outcomeLine), "ops@example.com", "root@example.com", 1)
	if tampered == string(outcomeLine) {
		t.Fatal("tamper did not change the line")
	}
	add("v2_tampered_approver", false, "v2 outcome with the approver changed after signing", []byte(tampered))

	tr := *attempt
	tr.Reasons = []string{"policy_deny"}
	add("v2_tampered_reasons", false, "v2 attempt with its reason changed after signing", mustLine(t, &tr))

	sv1 := *attempt
	signV1(key, &sv1)
	add("v2_signed_sig_v1", false, "v:2 receipt carrying a sig_v1 signature over the v1 payload (a downgrade)", mustLine(t, &sv1))

	sv1b := *attempt
	sv1b.Signature = sigV1Prefix + hex.EncodeToString(ed25519.Sign(key, attempt.canonicalV2()))
	add("v2_payload_labelled_sig_v1", false, "v:2 receipt whose v2 signature is relabelled sig_v1", mustLine(t, &sv1b))

	nov := *attempt
	nov.V = 0
	signV1(key, &nov)
	add("v2_fields_without_v_sig_v1", false, "no v field but v2 fields set, signed sig_v1: the signature does not cover them", mustLine(t, &nov))

	nov2 := *attempt
	nov2.V = 0
	nov2.Signature = attempt.Signature
	add("sig_v2_without_v", false, "sig_v2 signature on a receipt without v:2", mustLine(t, &nov2))

	wk := *attempt
	wk.KeyID = KeyID(other.Public().(ed25519.PublicKey))
	signV2(other, &wk)
	add("v2_unknown_key", false, "v2 receipt signed by a key other than the file's public key", mustLine(t, &wk))

	wkid := *attempt
	wkid.KeyID = "0000000000000000"
	signV2(key, &wkid)
	add("v2_wrong_kid", false, "v2 receipt signed by the right key but naming another kid", mustLine(t, &wkid))

	tv1 := *v1
	tv1.Decision = "deny"
	add("v1_tampered", false, "v1 receipt with a field changed after signing", mustLine(t, &tv1))

	return &sdkVectorFile{
		Comment:   "Proxy receipt test vectors for the SDK verifiers. Generated by proxy/internal/receipts/sdk_vectors_test.go; do not edit by hand (OVARA_WRITE_SDK_VECTORS=1 go test ./internal/receipts -run TestSDKVectors).",
		PublicKey: hex.EncodeToString(pub),
		KeyID:     kid,
		Vectors:   vecs,
	}, chain
}

func TestSDKVectors(t *testing.T) {
	file, chain := buildSDKVectors(t)
	pub, _ := hex.DecodeString(file.PublicKey)
	ring := SingleKey(ed25519.PublicKey(pub))

	// Each vector verifies (or not) on its own, as a one-line cut of a chain.
	dir := t.TempDir()
	for i, v := range file.Vectors {
		r, err := parseLine([]byte(v.Line))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		p := filepath.Join(dir, v.Name+".jsonl")
		if err := os.WriteFile(p, []byte(v.Line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res, _, _ := verifySegment(p, ring, Segment{After: i + 1, PrevHash: r.PrevHash})
		if res.Valid != v.Valid {
			t.Errorf("%s: Go verifier says valid=%v (%s), vector says %v", v.Name, res.Valid, res.Reason, v.Valid)
		}
	}

	// The valid vectors form a whole chain: v1 receipts, then v2.
	p := filepath.Join(dir, "chain.jsonl")
	_ = os.WriteFile(p, append(bytes.Join(chain, []byte{'\n'}), '\n'), 0o600)
	if res := VerifyFile(p, ed25519.PublicKey(pub)); !res.Valid || res.Total != len(chain) || res.V1 != 2 {
		t.Fatalf("vector chain: %+v", res)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(file); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OVARA_WRITE_SDK_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(sdkVectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sdkVectorsPath, buf.Bytes(), 0o644); err != nil { //nolint:gosec // a committed test fixture, meant to be readable
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(sdkVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with OVARA_WRITE_SDK_VECTORS=1)", sdkVectorsPath, err)
	}
	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("%s is out of date with the proxy's receipt encoding: regenerate with OVARA_WRITE_SDK_VECTORS=1 go test ./internal/receipts -run TestSDKVectors", sdkVectorsPath)
	}
}

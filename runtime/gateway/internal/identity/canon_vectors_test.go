package identity

// Cross-language canonicalization vectors (P1.1 §11): the Python SDK
// (ovara_sdk.canon) must produce byte-identical payloads, and a chain
// signed by the Python SDK must verify against the Go validator.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// Vectors generated from the Go implementation and asserted identical
// in sdk/python (canon vectors test). Cover: multi-action, Unicode
// fields, empty optional fields, negative/zero timestamps.
func TestCanonVectors(t *testing.T) {
	hop1 := models.Authority{
		Issuer: "issuer-1", SubjectID: "ag_abc", Audience: "gw-A",
		ResourceScope: "https://api.github.com/*", Actions: []string{"shell", "exec"},
		ExpiresAt: time.Unix(1700000000, 0), DelegatedAt: time.Unix(1690000000, 0),
		Nonce: "n-fixed-1",
	}
	got := hex.EncodeToString(hopPayload([]models.Authority{hop1}, 0, ""))
	want := "000000086973737565722d310000000661675f6162630000000467772d410000001868747470733a2f2f6170692e6769746875622e636f6d2f2a00000002000000057368656c6c0000000465786563000000006553f1000000000064bb5a80000000096e2d66697865642d3100000000"
	if got != want {
		t.Fatalf("hop1 mismatch:\n got %s\nwant %s", got, want)
	}

	hop2 := models.Authority{
		Issuer: "issuer-ünïcode-根", SubjectID: "ag_日本語",
		ResourceScope: "*", DelegatedAt: time.Unix(0, 0),
	}
	got = hex.EncodeToString(hopPayload([]models.Authority{hop2}, 0, ""))
	want = "000000146973737565722dc3bc6ec3af636f64652de6a0b90000000c61675fe697a5e69cace8aa9e00000000000000012a00000000fffffff1886e090000000000000000000000000000000000"
	if got != want {
		t.Fatalf("hop2 mismatch:\n got %s\nwant %s", got, want)
	}

	lease := &models.CapabilityLease{
		LeaseID: "lse_1", Issuer: "ovara", Subject: "ag_abc", Audience: "gw-A",
		AllowedActions: []string{"shell"}, ResourceScope: "repo://org/*",
		Expiry: time.Unix(1700000000, 0), IssuedAt: time.Unix(1690000000, 0),
		DelegationDepth: 2,
	}
	got = hex.EncodeToString(leasePayload(lease))
	want = "000000056c73655f31000000056f766172610000000661675f6162630000000467772d4100000001000000057368656c6c0000000c7265706f3a2f2f6f72672f2a000000006553f1000000000064bb5a8000000002"
	if got != want {
		t.Fatalf("lease mismatch:\n got %s\nwant %s", got, want)
	}
}

// A hop signed by the Python SDK (cryptography.ed25519 over
// canon.hop_payload bytes) must verify in the Go validator — proves
// signer/verifier interoperability, not just byte-level equality.
func TestCanon_PythonSignedChainVerifies(t *testing.T) {
	pub, _ := hex.DecodeString("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
	sig, _ := base64.StdEncoding.DecodeString("c9Yeq/w6YyW13j1ZZ/TkcIMygQCY6zkgqK/MfjPe5yJUM68lpfmQNnN/f50WTNB/bJDCrYCfwx1BDbaNcZEIBw==")

	v := NewValidatorWithTrustedKeys(map[string][]byte{"issuer-py": pub})
	chain := &models.DelegationChain{
		Authorities: []models.Authority{{
			Issuer: "issuer-py", SubjectID: "ag_py", Audience: "gw-A",
			ResourceScope: "repo://org/*", Actions: []string{"shell"},
			ExpiresAt: time.Unix(4102444800, 0), DelegatedAt: time.Unix(1690000000, 0),
			Nonce: "py-nonce-1", Signature: sig,
		}},
		Depth: 1,
	}
	if r := v.ValidateDelegationChain(chain, "ag_py", nil); !r.Valid {
		t.Fatalf("python-signed chain must verify: %v", r.Reasons)
	}
	if !ed25519.Verify(pub, hopPayload(chain.Authorities, 0, ""), sig) {
		t.Fatal("raw signature check failed")
	}
}

// Two-hop Python-signed chain (issuer-A → issuer-B → ag_py2): verifies
// cross-language linkage — hop1's signature covers hop0's signature hex.
func TestCanon_PythonSignedTwoHopChain(t *testing.T) {
	pubA, _ := hex.DecodeString("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
	pubB, _ := hex.DecodeString("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
	sig0, _ := base64.StdEncoding.DecodeString("FYR0TF/WHCU+FJSThnFueUHkPI0rZJicqV5x7dRZ/ZT0QO2awn3gcfvN/4p7k/atHVAUdvI/3laMhg6qrIkJDg==")
	sig1, _ := base64.StdEncoding.DecodeString("LfMycu6IxWEgH9Wd0okoZgF1p4jDpYC23AXgBzmbqo8PyE6WYvS1PIL1acINfNrreYiDvxjQvIWkNtzYYEKdBw==")

	v := NewValidatorWithTrustedKeys(map[string][]byte{"issuer-A": pubA, "issuer-B": pubB})
	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "issuer-A", SubjectID: "issuer-B", ResourceScope: "*",
				Actions: []string{"shell", "exec"},
				ExpiresAt: time.Unix(4102444800, 0), DelegatedAt: time.Unix(1690000000, 0),
				Signature: sig0},
			{Issuer: "issuer-B", SubjectID: "ag_py2", ResourceScope: "repo://org/*",
				Actions: []string{"shell"},
				ExpiresAt: time.Unix(4102444800, 0), DelegatedAt: time.Unix(1690000100, 0),
				Nonce: "py2hop-nonce", Signature: sig1},
		},
		Depth: 2,
	}
	if r := v.ValidateDelegationChain(chain, "ag_py2", nil); !r.Valid {
		t.Fatalf("python 2-hop chain must verify: %v", r.Reasons)
	}
}

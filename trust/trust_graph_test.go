package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestTrustGraph_AddOrganization(t *testing.T) {
	tg := NewTrustGraph()
	err := tg.AddOrganization("acme.com", "Acme Corp", nil)
	if err != nil {
		t.Fatalf("AddOrganization failed: %v", err)
	}

	err = tg.AddOrganization("acme.com", "Acme Corp", nil)
	if err == nil {
		t.Error("expected duplicate organization error")
	}
}

func TestTrustGraph_RemoveOrganization(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("test.com", "Test Org", nil)

	err := tg.RemoveOrganization("test.com")
	if err != nil {
		t.Fatalf("RemoveOrganization failed: %v", err)
	}

	err = tg.RemoveOrganization("test.com")
	if err == nil {
		t.Error("expected error for missing organization")
	}
}

func TestTrustGraph_Federate(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := tg.Federate("a.com", "b.com", 0.8, [][]byte{pub})
	if err != nil {
		t.Fatalf("Federate failed: %v", err)
	}

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(neighbors))
	}
	if neighbors[0].TrustLevel != 0.8 {
		t.Errorf("trust level = %v, want 0.8", neighbors[0].TrustLevel)
	}
	if !neighbors[0].Active {
		t.Error("federation should be active")
	}
}

func TestTrustGraph_RevokeFederation(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	tg.Federate("a.com", "b.com", 0.9, nil)
	err := tg.RevokeFederation("a.com", "b.com")
	if err != nil {
		t.Fatalf("RevokeFederation failed: %v", err)
	}

	neighbors := tg.GetNeighbors("a.com")
	if neighbors[0].Active {
		t.Error("federation should be inactive after revocation")
	}
}

func TestTrustGraph_ComputeTrustPath_Direct(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.7, nil)

	path, err := tg.ComputeTrustPath("a.com", "b.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath failed: %v", err)
	}
	if !path.IsDirect() {
		t.Error("direct federation should have depth 1")
	}
	if path.Domains[0] != "a.com" || path.Domains[1] != "b.com" {
		t.Errorf("path domains = %v, want [a.com b.com]", path.Domains)
	}
}

func TestTrustGraph_ComputeTrustPath_Transitive(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("c.com", "Org C", nil)

	tg.Federate("a.com", "b.com", 0.9, nil)
	tg.Federate("b.com", "c.com", 0.8, nil)

	path, err := tg.ComputeTrustPath("a.com", "c.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath (transitive) failed: %v", err)
	}
	if path.Depth != 2 {
		t.Errorf("transitive path depth = %d, want 2", path.Depth)
	}
	if len(path.Domains) != 3 {
		t.Errorf("transitive path domains = %v, want 3 domains", path.Domains)
	}
}

func TestTrustGraph_ComputeTrustPath_NoPath(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	_, err := tg.ComputeTrustPath("a.com", "b.com")
	if err == nil {
		t.Error("expected error for no trust path")
	}
}

func TestTrustGraph_ComputeTrustPath_Self(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("self.com", "Self Org", nil)

	path, err := tg.ComputeTrustPath("self.com", "self.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath (self) failed: %v", err)
	}
	if path.TrustScore != 1.0 {
		t.Errorf("self trust score = %v, want 1.0", path.TrustScore)
	}
	if path.Depth != 0 {
		t.Errorf("self path depth = %d, want 0", path.Depth)
	}
}

func TestTrustGraph_GetAllOrganizations(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("a.com", "Org A", nil)

	orgs := tg.GetAllOrganizations()
	if len(orgs) != 2 {
		t.Fatalf("expected 2 organizations, got %d", len(orgs))
	}
	if orgs[0].Domain != "a.com" {
		t.Errorf("organizations should be sorted by domain, got %s first", orgs[0].Domain)
	}
}

func TestTrustGraph_Snapshot(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.5, nil)

	snap := tg.Snapshot()
	if snap["node_count"].(int) != 2 {
		t.Errorf("snapshot node_count = %v, want 2", snap["node_count"])
	}
	if snap["edge_count"].(int) != 1 {
		t.Errorf("snapshot edge_count = %v, want 1", snap["edge_count"])
	}
}

func TestCrossOrgReceipt_SignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	receipt := &CrossOrgReceipt{
		ReceiptID:      "rcpt_001",
		DecisionID:     "dec_001",
		IssuingGateway: "gw_a",
		IssuingOrg:     "acme.com",
		ActionType:     "shell.execute",
		Resource:       "sudo",
		Decision:       "deny",
		AgentIdentity:  "agt_abc123",
		TrustScore:     0.85,
		Timestamp:      time.Now().UTC(),
	}

	err := SignCrossOrgReceipt(receipt, priv)
	if err != nil {
		t.Fatalf("SignCrossOrgReceipt failed: %v", err)
	}
	if len(receipt.Signature) == 0 {
		t.Fatal("signature should not be empty")
	}

	if !receipt.Verify(pub) {
		t.Error("receipt verification failed with correct public key")
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if receipt.Verify(wrongPub) {
		t.Error("receipt verification succeeded with wrong public key")
	}
}

func TestCrossOrgReceipt_VerifyTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	receipt := &CrossOrgReceipt{
		ReceiptID:      "rcpt_001",
		DecisionID:     "dec_001",
		IssuingGateway: "gw_a",
		IssuingOrg:     "acme.com",
		ActionType:     "shell.execute",
		Resource:       "sudo",
		Decision:       "deny",
		AgentIdentity:  "agt_abc123",
		TrustScore:     0.85,
		Timestamp:      time.Now().UTC(),
	}

	SignCrossOrgReceipt(receipt, priv)
	receipt.Decision = "allow"

	if receipt.Verify(pub) {
		t.Error("tampered receipt should fail verification")
	}
}

func TestFederatedIdentity_Basic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	digest := "sha256:abc123"

	fid := &FederatedIdentity{
		IdentityDigest: digest,
		Domain:         "acme.com",
		SigningKey:     priv,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	}

	if fid.IdentityDigest != digest {
		t.Errorf("IdentityDigest = %v, want %v", fid.IdentityDigest, digest)
	}
	if fid.Domain != "acme.com" {
		t.Errorf("Domain = %v, want acme.com", fid.Domain)
	}
}

func TestTrustPath_Hash(t *testing.T) {
	path := &TrustPath{
		Domains:    []TrustDomain{"a.com", "b.com", "c.com"},
		TrustScore: 0.72,
		Depth:      2,
	}

	hash1 := path.Hash()
	hash2 := path.Hash()

	if hash1 != hash2 {
		t.Error("TrustPath.Hash should be deterministic")
	}
	if len(hash1) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA-256 hex)", len(hash1))
	}
}

func TestTrustGraph_TrustLevelBounds(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	err := tg.Federate("a.com", "b.com", -0.1, nil)
	if err == nil {
		t.Error("expected error for negative trust level")
	}

	err = tg.Federate("a.com", "b.com", 1.5, nil)
	if err == nil {
		t.Error("expected error for trust level > 1")
	}
}

func TestTrustGraph_Neighbors_Empty(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 0 {
		t.Errorf("expected 0 neighbors, got %d", len(neighbors))
	}
}

func TestTrustGraph_UpdateFederation(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	tg.Federate("a.com", "b.com", 0.5, nil)
	tg.Federate("a.com", "b.com", 0.9, nil)

	neighbors := tg.GetNeighbors("a.com")
	if neighbors[0].TrustLevel != 0.9 {
		t.Errorf("trust level after update = %v, want 0.9", neighbors[0].TrustLevel)
	}
}

func TestTrustGraph_RemoveOrgClearsEdges(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("c.com", "Org C", nil)

	tg.Federate("a.com", "b.com", 0.5, nil)
	tg.Federate("a.com", "c.com", 0.5, nil)
	tg.RemoveOrganization("b.com")

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 1 {
		t.Errorf("expected 1 neighbor after removal, got %d", len(neighbors))
	}
	if neighbors[0].TargetOrg != "c.com" {
		t.Errorf("remaining neighbor = %v, want c.com", neighbors[0].TargetOrg)
	}
}

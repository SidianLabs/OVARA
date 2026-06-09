package identity

import (
	"testing"
	"time"
)

func TestIssueCapabilityLease_Succeeds(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell", "git.push"}, "repo:example/*", 30, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl.LeaseID == "" {
		t.Error("lease_id is empty")
	}
	if cl.Issuer != issuer.ID {
		t.Errorf("issuer = %s, want %s", cl.Issuer, issuer.ID)
	}
	if cl.Subject != "agent-2" {
		t.Errorf("subject = %s, want agent-2", cl.Subject)
	}
	if cl.DelegationDepth != 2 {
		t.Errorf("delegation_depth = %d, want 2", cl.DelegationDepth)
	}
	if len(cl.Signature) == 0 {
		t.Error("signature is empty")
	}
	if cl.Expiry.Before(time.Now().UTC()) {
		t.Error("expiry is in the past")
	}
}

func TestIssueCapabilityLease_RequiresActiveIssuer(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	issuer.Revoke()

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for revoked issuer")
	}
}

func TestIssueCapabilityLease_RequiresActions(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", nil, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for nil allowed_actions")
	}

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", []string{}, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for empty allowed_actions")
	}
}

func TestIssueCapabilityLease_RequiresPositiveTTL(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 0, 0)
	if err == nil {
		t.Error("expected error for zero ttl")
	}

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", -1, 0)
	if err == nil {
		t.Error("expected error for negative ttl")
	}
}

func TestIssueCapabilityLease_RejectsNilIssuer(t *testing.T) {
	_, err := IssueCapabilityLease(nil, nil, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for nil issuer")
	}
}

func TestIssueCapabilityLease_RejectsNegativeDelegationDepth(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, -1)
	if err == nil {
		t.Error("expected error for negative delegation depth")
	}
}

func TestCapabilityLease_Verify(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cl.Verify(issuer.PublicKey) {
		t.Error("Verify returned false for valid signature")
	}
	if cl.Verify(nil) {
		t.Error("Verify returned true for nil key")
	}
	if cl.Verify([]byte("wrong-key")) {
		t.Error("Verify returned true for wrong key")
	}
}

func TestCapabilityLease_HasAction(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell", "git.push"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cl.HasAction("shell") {
		t.Error("HasAction returned false for shell")
	}
	if !cl.HasAction("git.push") {
		t.Error("HasAction returned false for git.push")
	}
	if cl.HasAction("git.pull") {
		t.Error("HasAction returned true for git.pull")
	}
}

func TestCapabilityLease_HasAction_Wildcard(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"*"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cl.HasAction("anything") {
		t.Error("HasAction returned false for wildcard lease")
	}
}

func TestCapabilityLease_ScopeCovers(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:example/web", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cl.ScopeCovers("repo:example/web") {
		t.Error("ScopeCovers returned false for exact match")
	}
	if cl.ScopeCovers("repo:other/repo") {
		t.Error("ScopeCovers returned true for non-matching resource")
	}
}

func TestCapabilityLease_ScopeCovers_Wildcard(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cl.ScopeCovers("anything") {
		t.Error("ScopeCovers returned false for wildcard scope")
	}
}

func TestCapabilityLease_IsExpired(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl.IsExpired() {
		t.Error("lease reported expired immediately after issue")
	}

	cl.Expiry = time.Now().UTC().Add(-1 * time.Hour)
	if !cl.IsExpired() {
		t.Error("lease should be expired")
	}
}

func TestCapabilityLease_Digest(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	d1 := cl.Digest()
	d2 := cl.Digest()
	if d1 != d2 {
		t.Error("digest is not deterministic")
	}
}

func TestCapabilityLease_CanDelegate(t *testing.T) {
	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cl.CanDelegate() {
		t.Error("CanDelegate returned false for depth=2")
	}

	clNoDel, err := IssueCapabilityLease(issuer, priv, "agent-3", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clNoDel.CanDelegate() {
		t.Error("CanDelegate returned true for depth=0")
	}
}

func TestCapabilityLease_Validate(t *testing.T) {
	cl := &CapabilityLease{}
	errs := cl.Validate()
	if len(errs) == 0 {
		t.Error("expected validation errors for empty lease")
	}
}

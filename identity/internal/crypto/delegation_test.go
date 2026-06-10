package crypto

import (
	"testing"
	"time"
)

func TestNewDelegationChain_ComputesHash(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "agt_1", DelegatedAt: time.Now().UTC()},
		{Issuer: "agt_1", SubjectID: "agt_2", DelegatedAt: time.Now().UTC()},
	}
	dc := NewDelegationChain(authorities)

	if dc.ChainHash == "" {
		t.Error("chain hash is empty")
	}
	if dc.Depth != 2 {
		t.Errorf("depth = %d, want 2", dc.Depth)
	}
	if !dc.Verify() {
		t.Error("Verify returned false for intact chain")
	}
}

func TestDelegationChain_Verify_DetectsTampering(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "agt_1", DelegatedAt: time.Now().UTC()},
	}
	dc := NewDelegationChain(authorities)

	dc.Authorities[0].SubjectID = "tampered"
	if dc.Verify() {
		t.Error("Verify returned true for tampered chain")
	}
}

func TestDelegationChain_RootAuthority(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "root"},
		{Issuer: "root", SubjectID: "leaf"},
	}
	dc := NewDelegationChain(authorities)

	root, ok := dc.RootAuthority()
	if !ok {
		t.Fatal("RootAuthority returned false")
	}
	if root.SubjectID != "root" {
		t.Errorf("root subject = %s, want root", root.SubjectID)
	}
}

func TestDelegationChain_LeafAuthority(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "root"},
		{Issuer: "root", SubjectID: "leaf"},
	}
	dc := NewDelegationChain(authorities)

	leaf, ok := dc.LeafAuthority()
	if !ok {
		t.Fatal("LeafAuthority returned false")
	}
	if leaf.SubjectID != "leaf" {
		t.Errorf("leaf subject = %s, want leaf", leaf.SubjectID)
	}
}

func TestDelegationChain_EmptyChain(t *testing.T) {
	dc := NewDelegationChain(nil)

	if dc.Depth != 0 {
		t.Errorf("depth = %d, want 0", dc.Depth)
	}
	if _, ok := dc.RootAuthority(); ok {
		t.Error("RootAuthority returned true for empty chain")
	}
	if _, ok := dc.LeafAuthority(); ok {
		t.Error("LeafAuthority returned true for empty chain")
	}
}

func TestDelegationChain_AllDelegators(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "agt_1", DelegatedAt: time.Now().UTC()},
		{Issuer: "agt_1", SubjectID: "agt_2", DelegatedAt: time.Now().UTC()},
		{Issuer: "agt_2", SubjectID: "agt_3", DelegatedAt: time.Now().UTC()},
	}
	dc := NewDelegationChain(authorities)

	delegators := dc.AllDelegators()
	if len(delegators) != 3 {
		t.Errorf("delegator count = %d, want 3", len(delegators))
	}
}

func TestDelegationChain_DepthExceeded(t *testing.T) {
	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "agt_1"},
		{Issuer: "agt_1", SubjectID: "agt_2"},
		{Issuer: "agt_2", SubjectID: "agt_3"},
	}
	dc := NewDelegationChain(authorities)

	if !dc.DepthExceeded(2) {
		t.Error("DepthExceeded(2) should be true for depth=3 chain")
	}
	if dc.DepthExceeded(3) {
		t.Error("DepthExceeded(3) should be false for depth=3 chain")
	}
}

func TestDelegationChain_Validate(t *testing.T) {
	dc := &DelegationChain{}
	errs := dc.Validate()
	if len(errs) != 1 {
		t.Errorf("expected 1 validation error, got %d", len(errs))
	}

	authorities := []Authority{
		{Issuer: "ovara", SubjectID: "agt_1"},
		{Issuer: "", SubjectID: ""},
	}
	dc = NewDelegationChain(authorities)
	errs = dc.Validate()
	if len(errs) != 2 {
		t.Errorf("expected 2 validation errors, got %d: %v", len(errs), errs)
	}
}

func TestDelegationChain_DifferentInputsProduceDifferentHashes(t *testing.T) {
	a1 := []Authority{
		{Issuer: "ovara", SubjectID: "agent-a"},
	}
	a2 := []Authority{
		{Issuer: "ovara", SubjectID: "agent-b"},
	}

	dc1 := NewDelegationChain(a1)
	dc2 := NewDelegationChain(a2)

	if dc1.ChainHash == dc2.ChainHash {
		t.Error("different chains should have different hashes")
	}
}

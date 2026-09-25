// C2-B A1 adversarial: the approver pin vs forged registry records.
// The gwidentity journal is hash-chain-sealed, NOT keyed — an
// attacker with fs-write can compute valid chain values. So the pin
// is the ONLY thing authenticating role=approver; these tests prove
// forged approver records die at fold, not at lookup convenience.
package gwidentity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeForgedLine(t *testing.T, path string, reg *Registry, rec *KeyRecord) {
	t.Helper()
	newChain, err := sealRecord(rec, reg.seq+1, reg.chain)
	if err != nil {
		t.Fatalf("seal forge: %v", err)
	}
	rec.Chain = hex.EncodeToString(newChain[:])
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal forge: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// C2B-REG-01: attacker appends a chain-VALID KeyRecord claiming
// role=approver under their own key → fold rejects it against the
// pin → Lookup fails closed (the store cannot absorb past it).
func TestAdvC2BReg_ForgedApproverRecordRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gwid.jsonl")
	reg, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	apPub, _, _ := ed25519.GenerateKey(nil)
	if err := reg.SetApproverPin(apPub); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := reg.AdmitApprover(apPub); err != nil {
		t.Fatalf("admit: %v", err)
	}

	// attacker forge: valid seq + valid chain (unkeyed sha256 — they
	// can compute it), but a pubkey they control, not the pin
	atkPub, _, _ := ed25519.GenerateKey(nil)
	forged := &KeyRecord{
		Kind: "key", GatewayID: ApproverID, KeyID: newKeyID(),
		PublicKey: hex.EncodeToString(atkPub), Role: "approver",
		State: KeyActive, CreatedAt: time.Now().UTC(), ActivatedAt: time.Now().UTC(),
		Generation: 2,
	}
	writeForgedLine(t, path, reg, forged)

	if _, err := reg.Lookup(ApproverID); err == nil ||
		!strings.Contains(err.Error(), "pinned approver root") {
		t.Fatalf("forged role=approver record survived fold: err=%v", err)
	}
}

// C2B-REG-02: pre-pin forgery — a record folded BEFORE the pin was
// configured still dies when the pin is set (SetApproverPin
// revalidates folded approver records).
func TestAdvC2BReg_PrePinForgeryRejectedAtPinSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gwid.jsonl")
	reg, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	atkPub, _, _ := ed25519.GenerateKey(nil)
	forged := &KeyRecord{
		Kind: "key", GatewayID: ApproverID, KeyID: newKeyID(),
		PublicKey: hex.EncodeToString(atkPub), Role: "approver",
		State: KeyActive, CreatedAt: time.Now().UTC(), ActivatedAt: time.Now().UTC(),
		Generation: 1,
	}
	writeForgedLine(t, path, reg, forged)
	// folds unchecked while pin unset — expected (can't validate yet)
	if _, err := reg.Lookup(ApproverID); err != nil {
		t.Fatalf("pre-pin fold should not error yet: %v", err)
	}
	// the moment the real pin is configured the forgery is caught
	apPub, _, _ := ed25519.GenerateKey(nil)
	if err := reg.SetApproverPin(apPub); err == nil ||
		!strings.Contains(err.Error(), "pinned approver root") {
		t.Fatalf("pre-pin forged record passed pin revalidation: err=%v", err)
	}
}

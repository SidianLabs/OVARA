package approval

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

func advSigner(t *testing.T) (*record.Signer, record.ResolveFunc) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := record.NewSigner(priv, "dom-test", "gw1", "k1")
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw == "gw1" && kid == "k1" {
			return pub, nil
		}
		return nil, errors.New("no key")
	}
	return signer, resolve
}

func appendApproval(t *testing.T, j *record.Journal, a *ApprovalRequest) {
	t.Helper()
	if _, _, err := j.Append("approval", a.ApprovalID, a, nil); err != nil {
		t.Fatal(err)
	}
}

func openBound(t *testing.T, path string, s *record.Signer, r record.ResolveFunc) (*FileBackedStore, error) {
	t.Helper()
	return NewFileBackedStore(path, &record.Binding{Signer: s, Resolve: r})
}

func mkApproval(id string, st Status) *ApprovalRequest {
	return &ApprovalRequest{
		ApprovalID: id, DecisionID: "dec_1", AgentID: "agt_a",
		ActionType: models.ActionType("shell"), Resource: "shell:ls",
		Status: st, CreatedAt: time.Now().UTC(),
	}
}

// STORE-03: legacy whole-file JSON refuses in signed mode.
func TestAdv21_STORE03_UnsignedApprovalFile(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "approvals.json")
	os.WriteFile(p, []byte(`{"apr_1":{"approval_id":"apr_1"}}`), 0o600)
	if _, err := openBound(t, p, signer, resolve); err == nil {
		t.Fatal("unsigned whole-file approvals opened in signed mode")
	}
}

// Approval fold table: pending→{approved,denied} only; a conflicting
// re-decision, an approved genesis, and genesis-over-tombstone all
// refuse; identical restatement stays legal (Update rewrites).
func TestAdv21_ApprovalFoldTable(t *testing.T) {
	signer, resolve := advSigner(t)

	// decision flip: pending → approved → denied must fail
	p := filepath.Join(t.TempDir(), "a.jsonl")
	j, _ := record.Open("approval", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	a := mkApproval("apr_1", StatusPending)
	appendApproval(t, j, a)
	d1 := *a
	d1.Status = StatusApproved
	d1.ResolvedBy = "op"
	appendApproval(t, j, &d1)
	d2 := d1
	d2.Status = StatusDenied
	appendApproval(t, j, &d2)
	j.Close()
	if st, err := openBound(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("approved→denied flip accepted")
	}

	// tombstoned id then genesis → fail
	p = filepath.Join(t.TempDir(), "a.jsonl")
	j, _ = record.Open("approval", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendApproval(t, j, a)
	j.Append(record.TypeTombstone, "apr_1", map[string]string{"state": "deleted"}, nil)
	appendApproval(t, j, a)
	j.Close()
	if st, err := openBound(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("genesis over tombstone accepted")
	}

	// same-state restatement OK
	p = filepath.Join(t.TempDir(), "a.jsonl")
	j, _ = record.Open("approval", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendApproval(t, j, a)
	appendApproval(t, j, a)
	j.Close()
	st, err := openBound(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("identical restatement rejected: %v", err)
	}
	st.journal.Close()

	// approved genesis refuses (a record that first appears approved
	// was never decided by this gateway)
	p = filepath.Join(t.TempDir(), "a.jsonl")
	j, _ = record.Open("approval", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendApproval(t, j, mkApproval("apr_2", StatusApproved))
	j.Close()
	if st, err := openBound(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("approved genesis accepted")
	}
}

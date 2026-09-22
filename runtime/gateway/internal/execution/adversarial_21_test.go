package execution

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

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

func appendExec(t *testing.T, j *record.Journal, e *Execution) {
	t.Helper()
	if _, _, err := j.Append("execution", e.ExecutionID, e, nil); err != nil {
		t.Fatal(err)
	}
}

func openBound(t *testing.T, path string, s *record.Signer, r record.ResolveFunc) (*FileBackedStore, error) {
	t.Helper()
	return NewFileBackedStoreWithRetention(path, 0, 0, 0, &record.Binding{Signer: s, Resolve: r})
}

// STORE-04: legacy executions file refuses in signed mode.
func TestAdv21_STORE04_UnsignedExecutionFile(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "exec.jsonl")
	os.WriteFile(p, []byte(`{"execution_id":"exe_1","state":"pending"}`+"\n"), 0o600)
	if _, err := openBound(t, p, signer, resolve); err == nil {
		t.Fatal("unsigned execution journal opened in signed mode")
	}
}

// Execution fold: pending/running genesis legal; terminal genesis
// illegal unless a compact envelope precedes it; terminal resurrection
// refused outright.
func TestAdv21_ExecutionFold(t *testing.T) {
	signer, resolve := advSigner(t)

	// terminal resurrection: succeeded→running must fail
	p := filepath.Join(t.TempDir(), "e.jsonl")
	j, _ := record.Open("execution", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	e := &Execution{ExecutionID: "exe_1", ActionType: "shell", Resource: "shell:ls", State: StateRunning}
	appendExec(t, j, e)
	done := *e
	done.State = StateSucceeded
	appendExec(t, j, &done)
	zomb := done
	zomb.State = StateRunning
	appendExec(t, j, &zomb)
	j.Close()
	if st, err := openBound(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("terminal resurrection accepted")
	}

	// terminal genesis without compact → fail
	p = filepath.Join(t.TempDir(), "e.jsonl")
	j, _ = record.Open("execution", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendExec(t, j, &Execution{ExecutionID: "exe_2", ActionType: "shell", State: StateSucceeded})
	j.Close()
	if st, err := openBound(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("terminal genesis without compact accepted")
	}

	// compact-then-terminal-genesis is the compaction-remnant shape → legal
	p = filepath.Join(t.TempDir(), "e.jsonl")
	j, _ = record.Open("execution", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendExec(t, j, e) // exe_1 running
	done2 := *e
	done2.State = StateSucceeded
	appendExec(t, j, &done2)
	j.Append(record.TypeCompact, "", map[string]any{"compacted_through": 2, "removed_ids": []string{"exe_9"}}, nil)
	appendExec(t, j, &Execution{ExecutionID: "exe_9", ActionType: "shell", State: StateSucceeded})
	j.Close()
	st, err := openBound(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("compact-remnant terminal genesis rejected: %v", err)
	}
	st.journal.Close()
}

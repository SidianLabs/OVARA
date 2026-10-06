package audit

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) (string, string, ed25519.PublicKey, *Log) {
	t.Helper()
	dir := t.TempDir()
	cpDir := t.TempDir()
	pub, key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	l, err := Open(filepath.Join(dir, "audit.jsonl"), key, FileSink{Dir: cpDir}, 3)
	if err != nil {
		t.Fatal(err)
	}
	return dir, cpDir, pub, l
}

func TestAppendVerifyRoundtrip(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	for i := 0; i < 7; i++ {
		if _, err := l.Append("decision", []byte(`{"outcome":"deny"}`)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	res, err := VerifyFile(l.path, pub, cpDir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Total != 7 || res.AnchoredThroughSeq != 6 || res.UnanchoredTail != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestTruncationDetected(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	for i := 0; i < 6; i++ {
		l.Append("decision", []byte(`{"i":`+string(rune('0'+i))+`}`))
	}
	data, _ := os.ReadFile(l.path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	os.WriteFile(l.path, []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600)
	// verify WITHOUT checkpoint dir: passes on truncated prefix —
	// documented: truncation detection requires a checkpoint.
	if _, err := VerifyFile(l.path, pub, ""); err != nil {
		t.Fatalf("prefix verify should pass: %v", err)
	}
	// WITH checkpoints: fails — checkpoint covers seq 6, log ends at 4.
	if _, err := VerifyFile(l.path, pub, cpDir); err == nil ||
		!strings.Contains(err.Error(), "records missing") {
		t.Fatalf("expected records-missing, got %v", err)
	}
}

func TestReorderDetected(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	for i := 0; i < 5; i++ {
		l.Append("decision", []byte(`{"k":1}`))
	}
	data, _ := os.ReadFile(l.path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[1], lines[3] = lines[3], lines[1]
	os.WriteFile(l.path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	if _, err := VerifyFile(l.path, pub, cpDir); err == nil {
		t.Fatal("reorder not detected")
	}
}

func TestFieldModificationDetected(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	l.Append("decision", []byte(`{"outcome":"allow"}`))
	data, _ := os.ReadFile(l.path)
	mod := strings.Replace(string(data), "allow", "deny", 1)
	os.WriteFile(l.path, []byte(mod), 0o600)
	if _, err := VerifyFile(l.path, pub, cpDir); err == nil {
		t.Fatal("modification not detected")
	}
}

func TestForgedCheckpointIgnored(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	// three appends trigger a legit auto-checkpoint (cpEvery=3)
	for i := 0; i < 3; i++ {
		l.Append("decision", []byte(`{}`))
	}
	// attacker writes a checkpoint with a different key
	evilPub, evilKey, _ := GenerateKey()
	evil := &Log{key: evilKey, seq: 99, prevHash: strings.Repeat("0", 64)}
	evil.hashes = [][]byte{[]byte("fake")}
	cp, _ := evil.emitCheckpointLocked()
	b, _ := json.Marshal(cp)
	os.WriteFile(filepath.Join(cpDir, "checkpoint_99_0.json"), b, 0o644)
	if _, err := LatestCheckpoint(cpDir, pub); err != nil {
		t.Fatalf("forged checkpoint should be skipped, error: %v", err)
	}
	// and evil's pubkey would validate it — proves sig check works
	got, err := LatestCheckpoint(cpDir, evilPub)
	if err != nil || got.TreeSize != 99 {
		t.Fatalf("evil checkpoint should verify under evil key: %v %+v", err, got)
	}
}

func TestEmptyLogIsError(t *testing.T) {
	dir, _, pub, _ := setup(t)
	if _, err := VerifyFile(filepath.Join(dir, "audit.jsonl"), pub, ""); err == nil {
		t.Fatal("empty log must not verify")
	}
}

func TestNoSiblingPubkeyFallback(t *testing.T) {
	// v1 SEC-0002: verify silently read receipt_pubkey.hex beside the
	// chain. Here: nil pub => error, full stop.
	_, _, _, l := setup(t)
	l.Append("decision", []byte(`{}`))
	if _, err := VerifyFile(l.path, nil, ""); err == nil {
		t.Fatal("verify must refuse without explicit key")
	}
}

func TestCorruptTailRefusesFork(t *testing.T) {
	_, _, pub, l := setup(t)
	l.Append("decision", []byte(`{}`))
	f, _ := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{garbage\n")
	f.Close()
	_, key, _ := GenerateKey()
	if _, err := Open(l.path, key, nil, 0); err == nil {
		t.Fatal("corrupt tail must refuse")
	}
	// wrong-key open must also fail self-verify (silently orphaning
	// a chain is the v1 sibling-key bug's cousin)
	_ = pub
}

func TestExplicitCheckpoint(t *testing.T) {
	_, cpDir, pub, l := setup(t)
	l.Append("decision", []byte(`{}`))
	cp, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.TreeSize != 1 {
		t.Fatalf("cp covers %d want 1", cp.TreeSize)
	}
	if _, err := VerifyFile(l.path, pub, cpDir); err != nil {
		t.Fatalf("verify against explicit cp: %v", err)
	}
}

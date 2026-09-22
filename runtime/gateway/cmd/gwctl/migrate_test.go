package main

// MIG-01..03: the 2.0→2.1 migration tool — idempotent re-run, honest
// import semantics, quarantine collision refusal.

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/replay"
	"ovara.runtime.gateway/internal/record"
)

func migSetup(t *testing.T) (*gwidentity.Registry, string, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := gwidentity.Open(filepath.Join(dir, "gwreg.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "gateway.key")
	priv, err := gwidentity.LoadOrCreateKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("gw1", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return r, keyFile, dir
}

// replayBinding rebuilds the signed-mode binding the server would use.
func replayBinding(t *testing.T, r *gwidentity.Registry, keyFile string) *record.Binding {
	t.Helper()
	priv, err := gwidentity.LoadOrCreateKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	rec := r.FindByPub("gw1", priv.Public().(ed25519.PublicKey))
	if rec == nil {
		t.Fatal("key not in registry")
	}
	return &record.Binding{
		Signer:  record.NewSigner(priv, r.DomainID(), "gw1", rec.KeyID),
		Resolve: receipt.RegistryResolver{Reg: r}.ResolvePublicKey,
	}
}

// MIG-02: replay import keeps live consume keys and drops expired and
// corrupt lines — then the signed journal enforces them on reopen.
func TestAdv21_MIG02_ReplayImportHonest(t *testing.T) {
	r, keyFile, dir := migSetup(t)

	live := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	dead := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	rp := filepath.Join(dir, "replay.jsonl")
	legacy := `{"k":"deleg","p":"live-1","e":"` + live + `"}` + "\n" +
		`{"k":"deleg","p":"dead-1","e":"` + dead + `"}` + "\n" +
		"garbage\n"
	os.WriteFile(rp, []byte(legacy), 0o600)

	runMigrate(r, "gw1", keyFile, "replay="+rp, true)

	fs, err := replay.OpenFile(rp, 0, replayBinding(t, r, keyFile))
	if err != nil {
		t.Fatalf("migrated replay journal won't open: %v", err)
	}
	exp := time.Now().Add(2 * time.Hour)
	if got := fs.Consume(replay.KindDelegation, "live-1", exp); got != replay.AlreadyConsumed {
		t.Fatalf("live key not imported: %v", got)
	}
	if got := fs.Consume(replay.KindDelegation, "dead-1", exp); got != replay.FirstConsume {
		t.Fatalf("expired key was imported: %v", got)
	}
	fs.Close()
	if _, err := os.Stat(rp + ".pre21"); err != nil {
		t.Fatal("quarantine copy missing")
	}
}

// MIG-01: a second run skips already-signed stores (idempotent).
func TestAdv21_MIG01_Idempotent(t *testing.T) {
	r, keyFile, dir := migSetup(t)
	rp := filepath.Join(dir, "replay.jsonl")
	os.WriteFile(rp, []byte(`{"k":"deleg","p":"k1","e":"2030-01-01T00:00:00Z"}`+"\n"), 0o600)
	runMigrate(r, "gw1", keyFile, "replay="+rp, true)
	first, _ := os.ReadFile(rp)
	runMigrate(r, "gw1", keyFile, "replay="+rp, true) // must not fatal
	second, _ := os.ReadFile(rp)
	if string(first) != string(second) {
		t.Fatal("second migrate mutated a signed journal")
	}
}

// MIG-03: quarantine collision — existing .pre21 refuses (subprocess:
// fatal() exits the process).
func TestAdv21_MIG03_QuarantineCollision(t *testing.T) {
	if os.Getenv("GWCTL_HELPER") == "1" {
		quarantine(os.Args[len(os.Args)-1], []byte("legacy"))
		return
	}
	p := filepath.Join(t.TempDir(), "replay.jsonl")
	os.WriteFile(p+".pre21", []byte("prior"), 0o600)
	cmd := exec.Command(os.Args[0], "-test.run=TestAdv21_MIG03")
	cmd.Env = append(os.Environ(), "GWCTL_HELPER=1")
	cmd.Args = append(cmd.Args, p)
	if err := cmd.Run(); err == nil {
		t.Fatal("quarantine over existing .pre21 did not refuse")
	}
}

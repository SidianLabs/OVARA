// P2.2 identity + credential lifecycle — unit matrix.
package idregistry

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tmpReg(t *testing.T) string {
	return filepath.Join(t.TempDir(), "identity.json")
}

// Seeded config credential authenticates to its RC1 principal — the
// migration invariant: identity id == old derived principal.
func TestSeed_PrincipalIsRC1Identity(t *testing.T) {
	r := NewInMemory()
	if err := r.SeedConfig([]string{"tok-agent-1"}, "agent"); err != nil {
		t.Fatal(err)
	}
	id, role, ok := r.Authenticate("tok-agent-1")
	if !ok {
		t.Fatal("seeded credential rejected")
	}
	want := PrincipalID("agent", "tok-agent-1")
	if id != want || role != "agent" {
		t.Fatalf("id=%q role=%q, want %q/agent", id, role, want)
	}
	if id[:3] != "ag_" {
		t.Fatalf("identity %q missing ag_ prefix", id)
	}
}

// Unknown/revoked/expired credentials all fail.
func TestAuthenticate_Failures(t *testing.T) {
	r := NewInMemory()
	r.SeedConfig([]string{"tok-a"}, "agent")
	if _, _, ok := r.Authenticate("tok-unknown"); ok {
		t.Fatal("unknown credential authenticated")
	}
	if err := r.RevokeToken("tok-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate("tok-a"); ok {
		t.Fatal("revoked credential authenticated")
	}
}

// Rotation: new credential binds to the SAME identity; old is
// dual-valid inside the grace window, dead after.
func TestRotate_StableIdentity(t *testing.T) {
	r := NewInMemory()
	r.SeedConfig([]string{"tok-c1"}, "agent")
	idA, _, _ := r.Authenticate("tok-c1")

	newTok, err := r.Rotate(idA, "tok-c2", 60)
	if err != nil {
		t.Fatal(err)
	}
	if newTok != "tok-c2" {
		t.Fatalf("rotate returned %q", newTok)
	}
	id2, _, ok := r.Authenticate("tok-c2")
	if !ok || id2 != idA {
		t.Fatalf("rotated credential id=%q ok=%v, want %q", id2, ok, idA)
	}
	// Old credential inside grace → same identity.
	id1, _, ok := r.Authenticate("tok-c1")
	if !ok || id1 != idA {
		t.Fatalf("in-grace old credential id=%q ok=%v, want %q", id1, ok, idA)
	}
}

func TestRotate_GraceExpiry(t *testing.T) {
	r := NewInMemory()
	r.SeedConfig([]string{"tok-c1"}, "agent")
	idA, _, _ := r.Authenticate("tok-c1")
	if _, err := r.Rotate(idA, "tok-c2", 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, _, ok := r.Authenticate("tok-c1"); ok {
		t.Fatal("superseded credential authenticated past grace")
	}
	if _, _, ok := r.Authenticate("tok-c2"); !ok {
		t.Fatal("new credential rejected after grace")
	}
}

// Persistence: register → reopen file → authenticate; revoke →
// reopen → still denied; rotate → reopen → new cred same identity.
func TestPersistence_AcrossRestart(t *testing.T) {
	path := tmpReg(t)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.SeedConfig([]string{"tok-op"}, "operator")
	id, tok, err := r.Register("agent", "", "tok-p1", nil)
	if err != nil {
		t.Fatal(err)
	}

	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	gotID, _, ok := r2.Authenticate("tok-p1")
	if !ok || gotID != id {
		t.Fatalf("post-restart auth id=%q ok=%v, want %q", gotID, ok, id)
	}
	if err := r2.RevokeToken(tok); err != nil {
		t.Fatal(err)
	}
	r3, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r3.Authenticate("tok-p1"); ok {
		t.Fatal("revoked credential authenticated after restart")
	}
}

// Non-resurrecting seed: a revoked config credential must NOT come
// back just because the config still lists it.
func TestSeed_NonResurrecting(t *testing.T) {
	path := tmpReg(t)
	r, _ := Open(path)
	r.SeedConfig([]string{"tok-a"}, "agent")
	r.RevokeToken("tok-a")
	r2, _ := Open(path)
	if err := r2.SeedConfig([]string{"tok-a"}, "agent"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r2.Authenticate("tok-a"); ok {
		t.Fatal("revoked credential resurrected by config seed")
	}
}

// Removing a token from config revokes its config-origin credential —
// config is the operator's source of truth for seeded creds.
func TestSeed_ConfigRemovalRevokes(t *testing.T) {
	r := NewInMemory()
	r.SeedConfig([]string{"tok-a", "tok-b"}, "agent")
	if err := r.SeedConfig([]string{"tok-b"}, "agent"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate("tok-a"); ok {
		t.Fatal("credential removed from config still authenticates")
	}
	if _, _, ok := r.Authenticate("tok-b"); !ok {
		t.Fatal("remaining config credential rejected")
	}
}

// Suspend kills every credential of the identity; resume restores.
func TestIdentity_SuspendResume(t *testing.T) {
	r := NewInMemory()
	id, tok, _ := r.Register("agent", "", "tok-s1", nil)
	if err := r.Transition(id, "suspend", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate(tok); ok {
		t.Fatal("suspended identity's credential authenticated")
	}
	// A second credential on the same identity also fails.
	r.Rotate(id, "tok-s2", 60)
	if _, _, ok := r.Authenticate("tok-s2"); ok {
		t.Fatal("suspended identity's rotated credential authenticated")
	}
	if err := r.Transition(id, "resume", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate("tok-s2"); !ok {
		t.Fatal("resumed identity's credential rejected")
	}
}

// Retired identity is a tombstone — no auth, no re-registration.
func TestIdentity_RetireTombstone(t *testing.T) {
	r := NewInMemory()
	id, tok, _ := r.Register("agent", "", "tok-r1", nil)
	if err := r.Transition(id, "retire", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate(tok); ok {
		t.Fatal("retired identity's credential authenticated")
	}
	if _, _, err := r.Register("agent", id, "tok-r2", nil); err == nil {
		t.Fatal("retired identity re-registered — tombstone violated")
	}
}

// A credential can never bind to two identities.
func TestRegister_NoCredentialRebind(t *testing.T) {
	r := NewInMemory()
	id1, _, _ := r.Register("agent", "", "tok-x", nil)
	if _, _, err := r.Register("agent", "", "tok-x", nil); err == nil {
		t.Fatal("same token registered to a second identity")
	}
	if _, err := r.Rotate(id1, "tok-x", 60); err == nil {
		t.Fatal("existing token re-bound via rotate")
	}
}

// Identity squatting: existing ids can't be re-registered; role
// prefix must match role.
func TestRegister_SquatAndRolePrefix(t *testing.T) {
	r := NewInMemory()
	id, _, _ := r.Register("agent", "", "tok-1", nil)
	if _, _, err := r.Register("agent", id, "tok-2", nil); err == nil {
		t.Fatal("existing identity re-registered")
	}
	if _, _, err := r.Register("agent", "op_evil1234", "tok-3", nil); err == nil {
		t.Fatal("agent registered an op_-prefixed identity")
	}
	if _, _, err := r.Register("operator", "ag_evil1234", "tok-4", nil); err == nil {
		t.Fatal("operator registered an ag_-prefixed identity")
	}
}

// Expired credential denies.
func TestCredential_Expiry(t *testing.T) {
	r := NewInMemory()
	past := time.Now().Add(-time.Hour).UTC()
	_, tok, _ := r.Register("agent", "", "", &past)
	if _, _, ok := r.Authenticate(tok); ok {
		t.Fatal("expired credential authenticated")
	}
	future := time.Now().Add(time.Hour).UTC()
	_, tok2, _ := r.Register("agent", "", "", &future)
	if _, _, ok := r.Authenticate(tok2); !ok {
		t.Fatal("unexpired credential rejected")
	}
}

// Migration: migrate → old identity dead, successor unaffected.
func TestIdentity_Migrate(t *testing.T) {
	r := NewInMemory()
	idA, tokA, _ := r.Register("agent", "", "tok-a", nil)
	idB, tokB, _ := r.Register("agent", "", "tok-b", nil)
	if err := r.Transition(idA, "migrate", idB); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Authenticate(tokA); ok {
		t.Fatal("migrated identity's credential authenticated")
	}
	if _, _, ok := r.Authenticate(tokB); !ok {
		t.Fatal("successor identity's credential rejected")
	}
}

// Concurrent auth vs revoke — whichever commits first wins; never a
// panic/corruption. Post-race, revoked must deny.
func TestConcurrent_AuthVsRevoke(t *testing.T) {
	r := NewInMemory()
	_, tok, _ := r.Register("agent", "", "tok-race", nil)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Authenticate(tok)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.RevokeToken(tok)
	}()
	wg.Wait()
	if _, _, ok := r.Authenticate(tok); ok {
		t.Fatal("revoked credential authenticated after race")
	}
}

// Concurrent registrations — no duplicate identities, no corruption.
func TestConcurrent_Register(t *testing.T) {
	r := NewInMemory()
	var wg sync.WaitGroup
	ids := make([]string, 16)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, _, err := r.Register("agent", "", "", nil)
			if err == nil {
				ids[i] = id
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if seen[id] {
			t.Fatalf("duplicate identity id %q", id)
		}
		seen[id] = true
	}
}

// Corrupt registry file fails open.
func TestOpen_CorruptFails(t *testing.T) {
	path := tmpReg(t)
	r, _ := Open(path)
	r.SeedConfig([]string{"tok-a"}, "agent")
	// Corrupt the file mid-write simulation.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{not json")
	f.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt registry opened — fail closed required")
	}
}

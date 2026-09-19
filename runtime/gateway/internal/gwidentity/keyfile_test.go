package gwidentity

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFile_Create0600AndReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gateway_key")
	priv, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("key file must be 0600, got %o", st.Mode().Perm())
	}
	priv2, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(priv2) {
		t.Fatal("reload must return the same key")
	}
	if len(priv2.Public().(ed25519.PublicKey)) != ed25519.PublicKeySize {
		t.Fatal("bad pubkey")
	}
}

func TestKeyFile_UnsafePermissions_Refused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gateway_key")
	if _, err := LoadOrCreateKey(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("group/world-readable key file must fail closed")
	}
}

func TestKeyFile_Corrupt_Refused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gateway_key")
	if err := os.WriteFile(p, []byte("not-hex\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("corrupt key file must fail")
	}
}

func TestKeyFile_WrongLength_Refused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gateway_key")
	if err := os.WriteFile(p, []byte(hex.EncodeToString([]byte("short"))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("wrong-length key must fail")
	}
}

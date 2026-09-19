package gwidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"ovara.runtime.gateway/internal/persist"
)

// Private-key file handling. The file holds hex(ed25519 private key),
// mode 0600, written atomically. On load, permissions are checked:
// any group/other access bit is "obviously unsafe" — fail closed.
// The private key is never logged, never in API responses, never in
// receipts, never in errors (errors name the path, not the material).

// GenerateKey creates a fresh ephemeral ed25519 keypair — used when no
// key file is configured (in-memory / runtime-only trust).
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// LoadOrCreateKey loads the private key at path, or generates and
// persists one if missing. Fails closed on unreadable/corrupt/unsafe-
// permission files — never silently substitutes a different key.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		st, serr := os.Stat(path)
		if serr != nil {
			return nil, fmt.Errorf("gateway key: stat %s: %w", path, serr)
		}
		if st.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("gateway key: %s has unsafe permissions %o — must be 0600", path, st.Mode().Perm())
		}
		priv, derr := hex.DecodeString(string(trimSpace(data)))
		if derr != nil || len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("gateway key: %s corrupt or wrong length", path)
		}
		return ed25519.PrivateKey(priv), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("gateway key: read %s: %w", path, err)
	}
	priv, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("gateway key: generate: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("gateway key: mkdir: %w", err)
	}
	if err := persist.WriteFileAtomic(path, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("gateway key: persist %s: %w", path, err)
	}
	return priv, nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

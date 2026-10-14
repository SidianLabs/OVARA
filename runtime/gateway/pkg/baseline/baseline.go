// Package baseline signs and verifies an organisation's policy baseline: a
// detached Ed25519 signature over the file's bytes, hex in <file>.sig,
// under a key whose public half the gateway pins (policy_baseline_pubkey in
// config.json). A project that can edit its own policy.json cannot then
// swap the baseline for a looser one.
package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeyGen makes a signing key pair: the public key (32 bytes, hex) to pin
// in config.json and the private key (64 bytes, hex) to keep with whoever
// signs the baseline.
func KeyGen() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// Sign returns the hex signature over data under the hex private key.
func Sign(data []byte, privHex string) (string, error) {
	priv, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("private key: want 64 bytes of hex (ovara policy baseline keygen)")
	}
	return hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), data)), nil
}

// Verify checks the hex signature over data under the hex public key.
func Verify(data []byte, sigHex, pubHex string) error {
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key: want 32 bytes of hex")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature: want 64 bytes of hex")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("the signature does not verify under this key: the file or the key changed")
	}
	return nil
}

// SigPath is where the detached signature of the file at path lives.
func SigPath(path string) string { return path + ".sig" }

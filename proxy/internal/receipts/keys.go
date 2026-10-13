package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A receipt key has a history. When the key is rotated, the old public key
// is kept in receipt_keys.jsonl (next to the public key file) with the
// window in which it was in use; when a key is revoked, the time it was
// revoked is recorded there. A receipt verifies only under a key whose
// window holds the receipt's timestamp and that was not revoked by then.
//
// Limits: the history is a plain file in the deployment directory, so
// whoever can write that directory can edit it (the threat model leaves
// that user out, and anchors are what catch a rewritten log). A stolen key
// can still sign receipts dated inside its window; revoking it as of the
// suspected theft is what bounds that.

// KeyRecord is one key in the history.
type KeyRecord struct {
	KeyID     string     `json:"kid"`
	Pub       string     `json:"pub"` // hex Ed25519 public key
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// KeyRing is the set of keys receipts may be signed with.
type KeyRing struct {
	recs []KeyRecord
	pubs map[string]ed25519.PublicKey // by kid
}

// KeyID names a public key: the first 16 hex digits of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// SingleKey is a ring holding one key with no window and no revocation.
func SingleKey(pub ed25519.PublicKey) *KeyRing {
	k := &KeyRing{pubs: map[string]ed25519.PublicKey{}}
	if len(pub) == ed25519.PublicKeySize {
		k.add(KeyRecord{KeyID: KeyID(pub), Pub: hex.EncodeToString(pub)}, pub)
	}
	return k
}

func (k *KeyRing) add(rec KeyRecord, pub ed25519.PublicKey) {
	k.recs = append(k.recs, rec)
	k.pubs[rec.KeyID] = pub
}

func (k *KeyRing) record(kid string) *KeyRecord {
	for i := range k.recs {
		if k.recs[i].KeyID == kid {
			return &k.recs[i]
		}
	}
	return nil
}

// Records returns the keys in the ring.
func (k *KeyRing) Records() []KeyRecord { return append([]KeyRecord(nil), k.recs...) }

// KeyHistoryPath is where the key history lives for a public key file.
func KeyHistoryPath(pubKeyFile string) string {
	return filepath.Join(filepath.Dir(pubKeyFile), "receipt_keys.jsonl")
}

// LoadKeyRing reads the current public key and the key history next to it.
func LoadKeyRing(pubKeyFile string) (*KeyRing, error) {
	raw, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, err
	}
	cur, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(cur) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not a valid ed25519 public key", pubKeyFile)
	}
	hist, err := readHistory(KeyHistoryPath(pubKeyFile))
	if err != nil {
		return nil, err
	}
	k := &KeyRing{pubs: map[string]ed25519.PublicKey{}}
	for _, rec := range hist {
		pub, err := hex.DecodeString(rec.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize || KeyID(pub) != rec.KeyID {
			return nil, fmt.Errorf("key history: bad entry for %q", rec.KeyID)
		}
		k.add(rec, pub)
	}
	if k.record(KeyID(cur)) == nil {
		k.add(KeyRecord{KeyID: KeyID(cur), Pub: hex.EncodeToString(cur)}, cur)
	}
	return k, nil
}

func readHistory(path string) ([]KeyRecord, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []KeyRecord
	for i, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var rec KeyRecord
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("key history %s line %d: %v", path, i+1, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func writeHistory(path string, recs []KeyRecord) error {
	var b bytes.Buffer
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return writeFileAtomic(path, b.Bytes(), 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// verify checks sigHex over msg for receipt r under the ring. v2 receipts
// name their key; v1 receipts do not, so every key is tried.
//
// The hex must be exactly what the writer produces (lower case): hex
// decoding accepts either case, so "ab" and "AB" would carry the same
// signature, and a line could be changed without failing to verify.
func (k *KeyRing) verify(r *Receipt, msg []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != sigHex {
		return errors.New("signature invalid")
	}
	var cands []KeyRecord
	if r.V >= 2 {
		rec := k.record(r.KeyID)
		if rec == nil {
			return errors.New("signed by an unknown key")
		}
		cands = []KeyRecord{*rec}
	} else {
		cands = k.recs
	}
	for _, rec := range cands {
		if !ed25519.Verify(k.pubs[rec.KeyID], msg, sig) {
			continue
		}
		ts := r.Timestamp
		switch {
		case rec.RevokedAt != nil && !ts.Before(*rec.RevokedAt):
			return fmt.Errorf("signed by key %s, revoked at %s", rec.KeyID, rec.RevokedAt.Format(time.RFC3339))
		case rec.NotAfter != nil && ts.After(*rec.NotAfter):
			return fmt.Errorf("signed by key %s after it was rotated out (%s)", rec.KeyID, rec.NotAfter.Format(time.RFC3339))
		case rec.NotBefore != nil && ts.Before(*rec.NotBefore):
			return fmt.Errorf("signed by key %s before it was in use (%s)", rec.KeyID, rec.NotBefore.Format(time.RFC3339))
		}
		return nil
	}
	return errors.New("signature invalid")
}

// RotateKey replaces the receipt signing key. The old key's public half
// stays in the history with its window closed at now; the new key's window
// opens at now. Run it while the proxy is stopped: a running proxy keeps
// signing with the old key, and those receipts would fail verification.
func RotateKey(keyFile, pubKeyFile string, now time.Time) (oldID, newID string, err error) {
	now = now.UTC()
	old, err := loadKey(keyFile)
	if err != nil {
		return "", "", fmt.Errorf("receipt key %s: %w", keyFile, err)
	}
	oldPub := old.Public().(ed25519.PublicKey)
	histPath := KeyHistoryPath(pubKeyFile)
	hist, err := readHistory(histPath)
	if err != nil {
		return "", "", err
	}
	oldID = KeyID(oldPub)
	found := false
	for i := range hist {
		if hist[i].KeyID == oldID {
			found = true
			if hist[i].NotAfter == nil || now.Before(*hist[i].NotAfter) {
				hist[i].NotAfter = &now
			}
		}
	}
	if !found {
		hist = append(hist, KeyRecord{KeyID: oldID, Pub: hex.EncodeToString(oldPub), NotAfter: &now})
	}
	newPub, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	newID = KeyID(newPub)
	hist = append(hist, KeyRecord{KeyID: newID, Pub: hex.EncodeToString(newPub), NotBefore: &now})
	// History first: if the key swap below does not happen, the proxy
	// refuses to start with the retired key and the rotation is rerun.
	if err := writeHistory(histPath, hist); err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(keyFile, []byte(hex.EncodeToString(newKey)), 0o600); err != nil {
		return "", "", err
	}
	if err := writeFileAtomic(pubKeyFile, []byte(hex.EncodeToString(newPub)), 0o644); err != nil {
		return "", "", err
	}
	return oldID, newID, nil
}

// RevokeKey marks a key revoked at the given time: receipts it signed at
// or after that time fail verification. which is a key id or a hex public
// key. Revoking the current key also stops the proxy from starting with
// it until the key is rotated.
func RevokeKey(pubKeyFile, which string, at time.Time) (string, error) {
	at = at.UTC()
	ring, err := LoadKeyRing(pubKeyFile)
	if err != nil {
		return "", err
	}
	var target *KeyRecord
	for i := range ring.recs {
		if ring.recs[i].KeyID == which || ring.recs[i].Pub == strings.ToLower(which) {
			target = &ring.recs[i]
		}
	}
	if target == nil {
		return "", fmt.Errorf("no receipt key %q in %s or its history", which, pubKeyFile)
	}
	histPath := KeyHistoryPath(pubKeyFile)
	hist, err := readHistory(histPath)
	if err != nil {
		return "", err
	}
	found := false
	for i := range hist {
		if hist[i].KeyID == target.KeyID {
			found = true
			if hist[i].RevokedAt == nil || at.Before(*hist[i].RevokedAt) {
				hist[i].RevokedAt = &at
			}
		}
	}
	if !found {
		rec := *target
		rec.RevokedAt = &at
		hist = append(hist, rec)
	}
	return target.KeyID, writeHistory(histPath, hist)
}

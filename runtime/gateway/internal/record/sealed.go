package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// SealedFile is the signed whole-file snapshot format for stores whose
// persistence is atomic-rewrite (idregistry, capabilities): a silent
// replacement or rollback is a signature
// failure or a file_seq regression under the tip-ledger floor.
type SealedFile struct {
	Sec  FileSec         `json:"_sec"`
	Data json.RawMessage `json:"data"`
}

type FileSec struct {
	V           int    `json:"v"`
	Store       string `json:"store"`
	DomainID    string `json:"domain_id"`
	FileSeq     uint64 `json:"file_seq"`
	PrevHash    string `json:"prev_file_sha256"`
	PayloadHash string `json:"payload_sha256"`
	KeyRef      KeyRef `json:"key_ref"`
	Sig         string `json:"sig"`
}

func filePayload(sec *FileSec) []byte {
	b := []byte("OVARA-FILE-" + sec.Store + "-V1")
	b = lp(b, sec.DomainID)
	b = lpu64(b, sec.FileSeq)
	b = lp(b, sec.PrevHash)
	b = lp(b, sec.PayloadHash)
	b = lp(b, sec.KeyRef.GatewayID)
	return lp(b, sec.KeyRef.KeyID)
}

// SealFile wraps payload in a signed snapshot. prev is the previous
// file's raw bytes (nil → file_seq starts at 1).
func SealFile(store string, s *Signer, payload, prev []byte, prevSeq uint64) ([]byte, error) {
	// RawMessage is compacted on marshal — hash the compacted form so
	// the sealed data field round-trips byte-identically.
	var pb bytes.Buffer
	if err := json.Compact(&pb, payload); err != nil {
		return nil, fmt.Errorf("seal %s: uncompacted payload: %w", store, err)
	}
	payload = pb.Bytes()
	sum := sha256.Sum256(payload)
	prevHash := ""
	if prev != nil {
		ph := sha256.Sum256(prev)
		prevHash = hex.EncodeToString(ph[:])
	}
	sec := FileSec{
		V:           Version,
		Store:       store,
		DomainID:    s.Domain(),
		FileSeq:     prevSeq + 1,
		PrevHash:    prevHash,
		PayloadHash: hex.EncodeToString(sum[:]),
		KeyRef:      s.Ref(),
	}
	sec.Sig = hex.EncodeToString(ed25519.Sign(s.priv, filePayload(&sec)))
	return json.Marshal(SealedFile{Sec: sec, Data: payload})
}

// OpenSealedFile verifies a sealed snapshot: domain, payload hash,
// signature via the registry resolver, and the floor rule
// (file_seq must dominate the ledger floor; equality requires the
// whole-file hash to match). Returns payload, file_seq, file hash.
// An unparseable or unsealed file fails closed.
func OpenSealedFile(store, path, domainID string, resolve ResolveFunc, floor Floor) (json.RawMessage, uint64, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if floor.Known {
				return nil, 0, "", fmt.Errorf("record %s: ledger floor seq %d exists but file is missing — store deleted or rolled back", store, floor.Seq)
			}
			return nil, 0, "", nil
		}
		return nil, 0, "", fmt.Errorf("record %s: read: %w", store, err)
	}
	if len(data) == 0 {
		return nil, 0, "", nil
	}
	var sf SealedFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, 0, "", fmt.Errorf("record %s: unparseable sealed file: %w", store, err)
	}
	if sf.Sec.V != Version {
		return nil, 0, "", fmt.Errorf("record %s: unsupported _sec version %d", store, sf.Sec.V)
	}
	if sf.Sec.Store != store {
		return nil, 0, "", fmt.Errorf("record %s: sealed store %q does not match %q — transplant", store, sf.Sec.Store, store)
	}
	if sf.Sec.DomainID != domainID {
		return nil, 0, "", fmt.Errorf("record %s: domain mismatch", store)
	}
	sum := sha256.Sum256(sf.Data)
	if hex.EncodeToString(sum[:]) != sf.Sec.PayloadHash {
		return nil, 0, "", fmt.Errorf("record %s: payload hash mismatch — contents modified", store)
	}
	pub, err := resolve(sf.Sec.KeyRef.GatewayID, sf.Sec.KeyRef.KeyID)
	if err != nil {
		return nil, 0, "", fmt.Errorf("record %s: key resolution failed: %w", store, err)
	}
	sig, err := hex.DecodeString(sf.Sec.Sig)
	if err != nil || !ed25519.Verify(pub, filePayload(&sf.Sec), sig) {
		return nil, 0, "", fmt.Errorf("record %s: signature invalid", store)
	}
	fileHash := TipHash(data)
	if floor.Known {
		if sf.Sec.FileSeq < floor.Seq {
			return nil, 0, "", fmt.Errorf("record %s: file_seq %d below ledger floor %d — rolled back", store, sf.Sec.FileSeq, floor.Seq)
		}
		if sf.Sec.FileSeq == floor.Seq && fileHash != floor.Hash {
			return nil, 0, "", fmt.Errorf("record %s: same file_seq with different hash — equivocation", store)
		}
	}
	return sf.Data, sf.Sec.FileSeq, fileHash, nil
}

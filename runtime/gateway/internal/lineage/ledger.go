// The transparency ledger — a minimal SCITT-style transparency
// service: an append-only, signed, hash-chained journal under a
// signing root distinct from the emitting gateway. Register() appends
// a statement digest and returns the countersigned Inclusion receipt;
// VerifyInclusion checks that receipt offline.
//
// Demo scope: file-backed, co-located. The production seam is
// Publisher — swap FileLedger for an HTTP/SCRAPI client and the
// format/verifier don't change.
package lineage

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"ovara.runtime.gateway/internal/record"
)

// incSigPrefix tags ledger countersignatures.
const incSigPrefix = "lininc_v1:"

// Publisher is the registration seam (SCITT: submit statement →
// receipt). Anything that registers a digest and returns a
// countersigned inclusion satisfies it — file ledger here, a remote
// transparency service in production.
type Publisher interface {
	Register(digest string) (*Inclusion, error)
}

// FileLedger is the demo transparency service: statement digests are
// appended to a record.Journal (so the ledger's own history is
// signed/chained/floor-checkable like every OVARA store) and each
// registration is countersigned under the ledger's key.
type FileLedger struct {
	domain string
	signer *record.Signer
	j      *record.Journal
}

// NewFileLedger opens (or creates) a ledger journal. domainID is the
// ledger's own trust domain — the countersignature binds it, so an
// inclusion minted by a different ledger never verifies under this
// domain's pinned key.
func NewFileLedger(path, domainID string, priv ed25519.PrivateKey, keyID string) (*FileLedger, error) {
	signer := record.NewSigner(priv, domainID, "ledger", keyID)
	pub := priv.Public().(ed25519.PublicKey)
	resolve := func(gwID, kid string) (ed25519.PublicKey, error) {
		if gwID != "ledger" || kid != keyID {
			return nil, fmt.Errorf("lineage ledger: unknown key %s/%s", gwID, kid)
		}
		return pub, nil
	}
	j, err := record.Open("lineage-ledger", path, domainID, signer, resolve, record.Floor{}, nil)
	if err != nil {
		return nil, fmt.Errorf("lineage ledger: %w", err)
	}
	return &FileLedger{domain: domainID, signer: signer, j: j}, nil
}

// Register appends a statement digest to the ledger and returns the
// countersigned inclusion receipt (SCITT's "transparent statement").
func (l *FileLedger) Register(digest string) (*Inclusion, error) {
	if l == nil {
		return nil, fmt.Errorf("lineage ledger: not configured")
	}
	seq, _, err := l.j.Append("inclusion", digest, map[string]string{"digest": digest}, nil)
	if err != nil {
		return nil, err
	}
	env := l.j.LastEnvelope()
	sig, err := l.signer.Sign(InclusionPayload(l.domain, digest, seq, env.Parent))
	if err != nil {
		return nil, fmt.Errorf("lineage ledger sign: %w", err)
	}
	return &Inclusion{
		LedgerDomain: l.domain,
		Seq:          seq,
		Parent:       env.Parent,
		Digest:       digest,
		KeyID:        l.signer.Ref().KeyID,
		Sig:          incSigPrefix + hex.EncodeToString(sig),
	}, nil
}

// VerifyInclusion is the offline receipt check: the countersignature
// must cover (ledger_domain, digest, seq, parent) under the pinned
// ledger key.
func VerifyInclusion(pub ed25519.PublicKey, inc *Inclusion) bool {
	if inc == nil || len(inc.Sig) <= len(incSigPrefix) || inc.Sig[:len(incSigPrefix)] != incSigPrefix {
		return false
	}
	sig, err := hex.DecodeString(inc.Sig[len(incSigPrefix):])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, InclusionPayload(inc.LedgerDomain, inc.Digest, inc.Seq, inc.Parent), sig)
}

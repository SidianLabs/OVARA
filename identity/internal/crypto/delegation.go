package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type Authority struct {
	Issuer      string    `json:"issuer"`
	SubjectID   string    `json:"subject_id"`
	DelegatedAt time.Time `json:"delegated_at,omitempty"`
}

type DelegationChain struct {
	Authorities []Authority `json:"authorities"`
	ChainHash   string      `json:"chain_hash,omitempty"`
	Depth       int         `json:"depth"`
}

func NewDelegationChain(authorities []Authority) *DelegationChain {
	dc := &DelegationChain{
		Authorities: authorities,
		Depth:       len(authorities),
	}
	dc.ChainHash = dc.computeHash()
	return dc
}

func (d *DelegationChain) computeHash() string {
	h := sha256.Sum256(canonicalJSON(d.Authorities))
	return hex.EncodeToString(h[:])
}

func (d *DelegationChain) Verify() bool {
	if d.ChainHash == "" {
		return false
	}
	// Depth must reflect the actual chain length, not a serialized claim.
	if d.Depth != len(d.Authorities) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(d.ChainHash), []byte(d.computeHash())) == 1
}

func (d *DelegationChain) RootAuthority() (Authority, bool) {
	if len(d.Authorities) == 0 {
		return Authority{}, false
	}
	return d.Authorities[0], true
}

func (d *DelegationChain) LeafAuthority() (Authority, bool) {
	if len(d.Authorities) == 0 {
		return Authority{}, false
	}
	return d.Authorities[len(d.Authorities)-1], true
}

func (d *DelegationChain) AllDelegators() []string {
	seen := make(map[string]bool)
	var result []string
	for _, a := range d.Authorities {
		if !seen[a.SubjectID] {
			seen[a.SubjectID] = true
			result = append(result, a.SubjectID)
		}
	}
	sort.Strings(result)
	return result
}

func (d *DelegationChain) DepthExceeded(maxDepth int) bool {
	// Recompute depth from the actual chain; the serialized Depth field is
	// not trustworthy on untrusted input.
	return len(d.Authorities) > maxDepth
}

func (d *DelegationChain) Validate() []string {
	var errs []string
	if len(d.Authorities) == 0 {
		errs = append(errs, "delegation chain must have at least one authority")
	}
	for i, a := range d.Authorities {
		if a.Issuer == "" {
			errs = append(errs, fmt.Sprintf("authority[%d]: issuer is required", i))
		}
		if a.SubjectID == "" {
			errs = append(errs, fmt.Sprintf("authority[%d]: subject_id is required", i))
		}
	}
	return errs
}

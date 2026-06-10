package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type Authority struct {
	Issuer     string    `json:"issuer"`
	SubjectID  string    `json:"subject_id"`
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
	payload := fmt.Sprintf("%d|", len(d.Authorities))
	for _, a := range d.Authorities {
		payload += fmt.Sprintf("%s|%s|%d|", a.Issuer, a.SubjectID, a.DelegatedAt.Unix())
	}
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

func (d *DelegationChain) Verify() bool {
	if d.ChainHash == "" {
		return false
	}
	return d.ChainHash == d.computeHash()
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
	return d.Depth > maxDepth
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

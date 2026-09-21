package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// principalID derives the canonical principal ID for an authenticated
// credential: a role prefix plus a truncated SHA-256 of the token. Two
// tokens never share an ID; the same token always yields the same ID
// (identity survives restarts). The prefix makes domains
// self-describing ("ag_…" vs "op_…") and prevents cross-domain
// collision if a token is ever dual-listed.
//
// This is the sole authoritative request identity. Caller-supplied
// fields (agent_identity.subject_id and friends) are advisory
// metadata — never a substitute for the credential-derived principal.
func principalID(role Role, token string) string {
	sum := sha256.Sum256([]byte(token))
	prefix := "ag_"
	if role == RoleOperator {
		prefix = "op_"
	}
	return prefix + hex.EncodeToString(sum[:])[:16]
}

// PrincipalID returns the canonical principal for this request, or ""
// when unauthenticated (open dev mode or exempt paths).
func PrincipalID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyPrincipalID{}).(string); ok {
		return v
	}
	return ""
}

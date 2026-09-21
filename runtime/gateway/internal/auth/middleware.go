package auth

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"sync"

	"ovara.runtime.gateway/internal/idregistry"
)

const (
	AuthHeader   = "Authorization"
	BearerPrefix = "Bearer "
)

// Role is the authorization domain a credential belongs to.
type Role string

const (
	// RoleOperator is gateway-root: approval resolution, continuations,
	// policy mutation, shield, capability revocation, admin, exports.
	RoleOperator Role = "operator"
	// RoleAgent is the minimal principal for agents/proxies: submit
	// decisions, create approvals for escalated decisions, read own
	// approval status. It can never resolve, mutate policy, or execute.
	RoleAgent Role = "agent"
)

// skipPaths lists endpoints reachable without a bearer token. Only pure
// liveness probes belong here. /v1/runtime/status is deliberately NOT
// exempt: it discloses enrollment file paths, policy source, receipt and
// approval counts, and gateway identity, so it requires authentication.
var skipPaths = map[string]bool{
	"/health": true,
	"/ready":  true,
}

// Agent-scope endpoints: the ONLY routes a RoleAgent token may reach —
// everything else is operator-only by default (fail-safe: newly added
// routes are operator surfaces until deliberately listed here). This is
// the exact call set the executor proxy uses, nothing more.
func agentAllowed(method, path string) bool {
	switch {
	case method == http.MethodPost && path == "/v1/runtime/check":
		return true
	case method == http.MethodPost && path == "/v1/runtime/batch-check":
		return true
	case method == http.MethodPost && path == "/v1/approval/create":
		return true
	// Poll approval status by id. Resolution verbs are POSTs; the
	// /pending list is a bulk read and stays operator-only.
	case method == http.MethodGet && strings.HasPrefix(path, "/v1/approval/") && path != "/v1/approval/pending":
		return true
	// whoami lets any authenticated credential resolve its stable
	// identity (proxy/agents need it under P2.2); it reveals only the
	// caller's own identity.
	case method == http.MethodGet && path == "/v1/whoami":
		return true
	}
	return false
}

func requiresOperator(method, path string) bool { return !agentAllowed(method, path) }

// ctxKeyPrincipal carries the authenticated role into handlers so
// security-sensitive identity fields (resolved_by, audit actors) are
// derived from the credential, never from caller-supplied JSON.
type ctxKeyPrincipal struct{}

// ctxKeyPrincipalID carries the canonical credential-derived principal
// ID (auth.PrincipalID) — the sole authoritative request identity.
type ctxKeyPrincipalID struct{}

// Principal returns the authenticated role for this request, or
// "unauthenticated" in open mode / on exempt paths.
func Principal(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyPrincipal{}).(string); ok && v != "" {
		return v
	}
	return "unauthenticated"
}

type Middleware struct {
	operatorTokens []string
	agentTokens    []string
	authEnabled    bool
	warnOnce       sync.Once
	registry       *idregistry.Registry
}

func NewMiddleware(tokens []string, authEnabled bool) *Middleware {
	return &Middleware{
		operatorTokens: tokens,
		authEnabled:    authEnabled,
	}
}

// NewMiddlewareWithAgents configures both token domains. When agentTokens
// is empty the middleware behaves exactly like the single-token version —
// every valid token is an operator.
func NewMiddlewareWithAgents(operatorTokens, agentTokens []string, authEnabled bool) *Middleware {
	return &Middleware{
		operatorTokens: operatorTokens,
		agentTokens:    agentTokens,
		authEnabled:    authEnabled,
	}
}

// SetRegistry installs the P2.2 identity registry. When set, a bearer
// token authenticates through its bound credential record → stable
// identity; when nil, the RC1 token-list + hash derivation applies.
func (m *Middleware) SetRegistry(r *idregistry.Registry) {
	m.registry = r
}

// roleFor returns the role a token belongs to. Empty = not a valid token.
func (m *Middleware) roleFor(provided string) Role {
	for _, token := range m.operatorTokens {
		if constantTimeCompare(token, provided) == 1 {
			return RoleOperator
		}
	}
	if len(m.agentTokens) == 0 {
		return "" // no agent domain configured
	}
	for _, token := range m.agentTokens {
		if constantTimeCompare(token, provided) == 1 {
			return RoleAgent
		}
	}
	return ""
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open mode: auth explicitly disabled.
		if !m.authEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Misconfiguration guard: auth enabled with no tokens at all must
		// fail closed, not silently open every endpoint. In registry mode
		// valid credentials may live only in the registry — the registry
		// itself fails closed on unknown credentials, so this guard
		// applies only to the token-list path.
		if m.registry == nil && len(m.operatorTokens) == 0 && len(m.agentTokens) == 0 {
			m.warnOnce.Do(func() {
				log.Printf("AUTH ERROR: auth_enabled=true but no tokens are configured — denying ALL requests until tokens are configured")
			})
			http.Error(w, `{"error":"authentication is enabled but no tokens are configured"}`, http.StatusServiceUnavailable)
			return
		}

		if skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get(AuthHeader)
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, BearerPrefix) {
			http.Error(w, `{"error":"invalid authorization format — use: Authorization: Bearer <token>"}`, http.StatusUnauthorized)
			return
		}

		provided := authHeader[len(BearerPrefix):]
		if provided == "" {
			http.Error(w, `{"error":"token is empty"}`, http.StatusUnauthorized)
			return
		}

		var role Role
		var principal string
		if m.registry != nil {
			// P2.2: the credential record resolves the stable identity —
			// the caller never chooses it. Fails closed on unknown,
			// revoked, superseded, expired, or suspended credentials.
			id, rrole, ok := m.registry.Authenticate(provided)
			if !ok {
				http.Error(w, `{"error":"invalid or inactive credential"}`, http.StatusUnauthorized)
				return
			}
			role = Role(rrole)
			principal = id
		} else {
			role = m.roleFor(provided)
			if role == "" {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			principal = principalID(role, provided)
		}

		// Authorization: agent-scope credentials never reach operator routes.
		if role == RoleAgent && requiresOperator(r.Method, r.URL.Path) {
			http.Error(w, `{"error":"insufficient privileges: this endpoint requires an operator-scope token"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyPrincipal{}, string(role))
		ctx = context.WithValue(ctx, ctxKeyPrincipalID{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func constantTimeCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

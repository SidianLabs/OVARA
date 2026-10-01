package auth

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"sync"
)

const (
	AuthHeader    = "Authorization"
	BearerPrefix  = "Bearer "
)

// skipPaths lists endpoints reachable without a bearer token. Only pure
// liveness probes belong here. /v1/runtime/status is deliberately NOT
// exempt: it discloses enrollment file paths, policy source, receipt and
// approval counts, and gateway identity, so it requires authentication.
var skipPaths = map[string]bool{
	"/health": true,
	"/ready":  true,
}

type Middleware struct {
	tokens      []string
	authEnabled bool
	warnOnce    sync.Once
}

func NewMiddleware(tokens []string, authEnabled bool) *Middleware {
	return &Middleware{
		tokens:      tokens,
		authEnabled: authEnabled,
	}
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open mode: auth explicitly disabled.
		if !m.authEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Misconfiguration guard: auth enabled with an empty token list must
		// fail closed, not silently open every endpoint. Deny all requests
		// and warn loudly once per process.
		if len(m.tokens) == 0 {
			m.warnOnce.Do(func() {
				log.Printf("AUTH ERROR: auth_enabled=true but operator_tokens is empty — denying ALL requests until tokens are configured")
			})
			http.Error(w, `{"error":"authentication is enabled but no operator tokens are configured"}`, http.StatusServiceUnavailable)
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

		found := false
		for _, token := range m.tokens {
			if constantTimeCompare(token, provided) == 1 {
				found = true
				break
			}
		}

		if !found {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func constantTimeCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	AuthHeader    = "Authorization"
	BearerPrefix  = "Bearer "
)

var skipPaths = map[string]bool{
	"/health":            true,
	"/ready":             true,
	"/v1/runtime/status": true,
}

type Middleware struct {
	tokens      []string
	authEnabled bool
}

func NewMiddleware(tokens []string, authEnabled bool) *Middleware {
	return &Middleware{
		tokens:      tokens,
		authEnabled: authEnabled,
	}
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open mode: auth disabled, or enabled but no tokens configured. The
		// startup log records this state once; we deliberately do not log per
		// request here to avoid flooding logs under load.
		if !m.authEnabled || len(m.tokens) == 0 {
			next.ServeHTTP(w, r)
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
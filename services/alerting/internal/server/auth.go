package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	authHeader   = "Authorization"
	bearerPrefix = "Bearer "
)

var authSkipPaths = map[string]bool{
	"/health": true,
}

// AuthMiddleware enforces bearer-token authentication on all routes except
// those in authSkipPaths. When constructed with no tokens it runs in open
// mode and allows every request — the startup log records that state.
type AuthMiddleware struct {
	tokens []string
}

func NewAuthMiddleware(tokens []string) *AuthMiddleware {
	return &AuthMiddleware{tokens: tokens}
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open mode: no tokens configured.
		if len(m.tokens) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		if authSkipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		header := r.Header.Get(authHeader)
		if header == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(header, bearerPrefix) {
			http.Error(w, `{"error":"invalid authorization format — use: Authorization: Bearer <token>"}`, http.StatusUnauthorized)
			return
		}

		provided := header[len(bearerPrefix):]
		if provided == "" {
			http.Error(w, `{"error":"token is empty"}`, http.StatusUnauthorized)
			return
		}

		found := false
		for _, token := range m.tokens {
			// Compare every token — no early break — so the loop does
			// not leak which position matched via timing.
			found = subtle.ConstantTimeCompare([]byte(token), []byte(provided)) == 1 || found
		}

		if !found {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

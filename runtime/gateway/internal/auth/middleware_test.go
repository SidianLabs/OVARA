package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_AuthEnabled_NoToken(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestMiddleware_AuthEnabled_ValidToken(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestMiddleware_AuthEnabled_WrongToken(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestMiddleware_AuthEnabled_MissingAuthHeader(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestMiddleware_AuthEnabled_InvalidFormat(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	req.Header.Set("Authorization", "Basic secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestMiddleware_AuthEnabled_EmptyToken(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestMiddleware_AuthDisabled(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, false)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/continuations", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestMiddleware_NoTokensConfigured_DeniesAll(t *testing.T) {
	// Auth enabled with an empty token list must fail closed: every request
	// is denied with 503 until operator_tokens is configured.
	mw := NewMiddleware([]string{}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{"/v1/continuations", "/v1/runtime/status", "/health"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set(AuthHeader, BearerPrefix+"any-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("path %s: expected status %d, got %d", path, http.StatusServiceUnavailable, rr.Code)
		}
	}
}

func TestMiddleware_SkipHealthPath(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestMiddleware_SkipReadyPath(t *testing.T) {
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ready", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestMiddleware_StatusPathRequiresAuth(t *testing.T) {
	// /v1/runtime/status exposes operational detail (enrollment file path,
	// policy source, receipt/approval counts, gateway identity) and must NOT
	// be reachable without a token.
	mw := NewMiddleware([]string{"secret-token"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/runtime/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}

	authed := httptest.NewRequest("GET", "/v1/runtime/status", nil)
	authed.Header.Set(AuthHeader, BearerPrefix+"secret-token")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, authed)

	if rr.Code != http.StatusOK {
		t.Errorf("authenticated: expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestMiddleware_MultipleTokens(t *testing.T) {
	mw := NewMiddleware([]string{"token-one", "token-two", "token-three"}, true)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	testCases := []struct {
		token   string
		wantOK  bool
	}{
		{"token-one", true},
		{"token-two", true},
		{"token-three", true},
		{"wrong-token", false},
		{"", false},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "/v1/continuations", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		got := rr.Code == http.StatusOK
		if got != tc.wantOK {
			t.Errorf("token %q: expected ok=%v, got ok=%v", tc.token, tc.wantOK, got)
		}
	}
}
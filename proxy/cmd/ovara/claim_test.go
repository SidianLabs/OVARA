package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.proxy/internal/gateway"
)

// Before a poller acts on an approval it claims it: once. A second claim
// reads as used, a gateway without the route is taken as before, and other
// statuses pass through untouched.
func TestSettleApprovalClaimsOnce(t *testing.T) {
	var claims int
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/approval/apr_1/claim":
			claims++
			if claims > 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "claimed": true})
		case "/v1/approval/apr_pending/claim":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "claimed": false})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gw.Close)
	c := gateway.New(gw.URL, "", "test")
	ctx := context.Background()
	if got := settleApproval(ctx, c, "apr_1", "approved"); got != "approved" {
		t.Fatalf("first: %q", got)
	}
	if got := settleApproval(ctx, c, "apr_1", "approved"); got != "used" {
		t.Fatalf("second: %q", got)
	}
	for _, st := range []string{"pending", "denied", "expired"} {
		if got := settleApproval(ctx, c, "apr_1", st); got != st {
			t.Errorf("%s passed through as %q", st, got)
		}
	}
	if claims != 2 {
		t.Fatalf("%d claims, want 2", claims)
	}
	// No route: an older gateway. Taken as approved.
	if got := settleApproval(ctx, c, "apr_norouteanywhere", "approved"); got != "approved" {
		t.Fatalf("older gateway: %q", got)
	}
}

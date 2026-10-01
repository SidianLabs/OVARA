package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckDecisions(t *testing.T) {
	for _, want := range []string{"allow", "deny", "escalate"} {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/runtime/check" || r.Method != "POST" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer tok" {
					t.Errorf("missing auth header")
				}
				body, _ := io.ReadAll(r.Body)
				var req map[string]any
				json.Unmarshal(body, &req)
				if req["action_type"] != "http.request" {
					t.Errorf("bad action_type %v", req["action_type"])
				}
				if req["resource"] != "GET https://x.com/" {
					t.Errorf("bad resource %v", req["resource"])
				}
				json.NewEncoder(w).Encode(Decision{Decision: want, DecisionID: "d1"})
			}))
			defer srv.Close()
			c := New(srv.URL, "tok", "test")
			d, err := c.Check(context.Background(), "GET", "https://x.com/")
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if d.Decision != want {
				t.Fatalf("got %q want %q", d.Decision, want)
			}
		})
	}
}

func TestCheckServerDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable
	c := New(url, "", "test")
	d, err := c.Check(context.Background(), "GET", "https://x.com/")
	if err == nil {
		t.Fatalf("expected error when gateway down, got decision %+v", d)
	}
	if d != nil {
		t.Fatalf("expected nil decision on error, got %+v", d)
	}
}

func TestCheckNon200(t *testing.T) {
	for _, code := range []int{400, 403, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		c := New(srv.URL, "", "test")
		d, err := c.Check(context.Background(), "GET", "https://x.com/")
		srv.Close()
		if err == nil || d != nil {
			t.Fatalf("status %d: expected error+nil decision, got d=%v err=%v", code, d, err)
		}
	}
}

func TestCheckBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "test")
	if _, err := c.Check(context.Background(), "GET", "https://x.com/"); err == nil {
		t.Fatal("expected decode error")
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCLI_Status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime/status" {
			json.NewEncoder(w).Encode(map[string]string{"gateway_id": "gw-test", "status": "ready"})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "status"}
	main()
}

func TestCLI_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "health"}
	main()
}

func TestCLI_ApiKeyHeader(t *testing.T) {
	var receivedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "--key", "sk_test_123", "health"}
	main()

	if receivedKey != "Bearer sk_test_123" {
		t.Errorf("Authorization header = %q, want Bearer sk_test_123", receivedKey)
	}
}

func TestCLI_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	code := 0
	origExit := osExit
	osExit = func(c int) { code = c }
	defer func() { osExit = origExit }()

	os.Args = []string{"ovara", "--gateway", server.URL, "health"}
	main()

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	cmd := captureStderr(func() {
		origExit := osExit
		osExit = func(code int) { _ = code }
		defer func() { osExit = origExit }()

		os.Args = []string{"ovara", "bogus"}
		main()
	})
	if !strings.Contains(cmd, "unknown command") {
		t.Errorf("expected 'unknown command' in stderr, got: %s", cmd)
	}
}

func TestCLI_CheckAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime/check" {
			json.NewEncoder(w).Encode(map[string]string{
				"decision": "allow",
			})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "check", "shell.execute", "sudo"}
	main()
}

func TestCLI_Usage(t *testing.T) {
	output := captureStderr(func() {
		origExit := osExit
		osExit = func(code int) { _ = code }
		defer func() { osExit = origExit }()

		os.Args = []string{"ovara"}
		main()
	})
	if !strings.Contains(output, "Usage:") {
		t.Errorf("expected usage in stderr, got: %s", output)
	}
}

func captureStderr(fn func()) string {
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = orig
	var buf [4096]byte
	n, _ := r.Read(buf[:])
	return string(buf[:n])
}

func TestCLI_ApprovalsList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/approvals" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"approvals": []map[string]string{
					{"id": "ap-1", "state": "pending"},
					{"id": "ap-2", "state": "pending"},
				},
			})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "approvals"}
	main()
}

func TestCLI_ApprovalsApprove(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/approval/ap-1/approve" {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			json.NewEncoder(w).Encode(map[string]string{"id": "ap-1", "state": "approved"})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "approvals", "approve", "ap-1"}
	main()

	if receivedBody != nil && receivedBody["action"] != "approve" {
		t.Errorf("action = %q, want approve", receivedBody["action"])
	}
}

func TestCLI_ApprovalsDeny(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/approval/ap-2/deny" {
			json.NewDecoder(r.Body).Decode(&receivedBody)
			json.NewEncoder(w).Encode(map[string]string{"id": "ap-2", "state": "denied"})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "approvals", "deny", "ap-2", "--reason=not ready"}
	main()

	if receivedBody != nil && receivedBody["reason"] != "not ready" {
		t.Errorf("reason = %q, want 'not ready'", receivedBody["reason"])
	}
}

func TestCLI_ApprovalsFilterState(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/approvals" {
			receivedQuery = r.URL.RawQuery
			json.NewEncoder(w).Encode(map[string]interface{}{"approvals": []map[string]string{}})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "approvals", "--state=approved"}
	main()

	if !strings.Contains(receivedQuery, "state=approved") {
		t.Errorf("query = %q, want state=approved", receivedQuery)
	}
}

func TestCLI_TrustScore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/trust/context" && r.URL.Query().Get("agent_id") == "agent-1" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"agent_id": "agent-1",
				"score":    0.95,
			})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "trust", "score", "agent-1"}
	main()
}

func TestCLI_TrustNoSubcommand(t *testing.T) {
	cmd := captureStderr(func() {
		os.Args = []string{"ovara", "trust"}
		main()
	})
	if !strings.Contains(cmd, "usage:") {
		t.Errorf("expected usage in stderr, got: %s", cmd)
	}
}

func TestCLI_VerifySingle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/receipts/rx-42" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"receipt_id": "rx-42",
				"valid":     true,
				"signature": "sig_v1",
			})
		}
	}))
	defer server.Close()

	os.Args = []string{"ovara", "--gateway", server.URL, "verify", "rx-42"}
	main()
}

func TestCLI_VerifyNoArgs(t *testing.T) {
	cmd := captureStderr(func() {
		os.Args = []string{"ovara", "verify"}
		main()
	})
	if !strings.Contains(cmd, "usage:") {
		t.Errorf("expected usage in stderr, got: %s", cmd)
	}
}

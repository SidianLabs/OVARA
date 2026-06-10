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

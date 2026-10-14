package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/creds"
)

func brokerStatuses(checks []check) map[string]string {
	out := map[string]string{}
	for _, c := range checks {
		if strings.HasPrefix(c.name, "credential broker ") {
			out[c.status] += c.detail + "\n"
		}
	}
	return out
}

// `ovara doctor` checks a GitHub App binding offline: the key file must be
// owner-only and an RSA key, the variables set, no secret written into
// proxy.json.
func TestDoctor_BrokerBindings(t *testing.T) {
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "var"), 0o700)
	keyPath := filepath.Join(dir, "var", "app.pem")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	t.Setenv("DOCTOR_APP_ID", "123")
	gh := creds.Binding{Host: "api.github.com", GitHubApp: &creds.GitHubApp{AppID: "${DOCTOR_APP_ID}", InstallationID: "42", PrivateKeyFile: "var/app.pem"}}
	cfg := &config.Config{Credentials: []creds.Binding{gh}}

	if st := brokerStatuses(auditCredentials(dir, cfg)); st["PASS"] == "" || st["FAIL"] != "" || st["WARN"] != "" {
		t.Fatalf("good binding: %v", st)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(keyPath, 0o644)
		if st := brokerStatuses(auditCredentials(dir, cfg)); !strings.Contains(st["FAIL"], "chmod 600") {
			t.Fatalf("group-readable key not flagged: %v", st)
		}
		_ = os.Chmod(keyPath, 0o600)
	}
	_ = os.WriteFile(keyPath, []byte("not a key"), 0o600)
	if st := brokerStatuses(auditCredentials(dir, cfg)); !strings.Contains(st["FAIL"], "private key") {
		t.Fatalf("unparsable key not flagged: %v", st)
	}

	unset := creds.Binding{Host: "api.github.com", GitHubApp: &creds.GitHubApp{AppID: "${DOCTOR_UNSET_APP_ID}", InstallationID: "42", PrivateKeyFile: "var/app.pem"}}
	if st := brokerStatuses(auditCredentials(dir, &config.Config{Credentials: []creds.Binding{unset}})); !strings.Contains(st["WARN"], "DOCTOR_UNSET_APP_ID") {
		t.Fatalf("unset variable not flagged: %v", st)
	}

	literal := creds.Binding{Host: "api.example.com", OAuth2: &creds.OAuth2{TokenURL: "https://auth.example.com/token", ClientID: "c", ClientSecret: "literal-secret-value"}}
	if st := brokerStatuses(auditCredentials(dir, &config.Config{Credentials: []creds.Binding{literal}})); !strings.Contains(st["FAIL"], "client_secret") {
		t.Fatalf("literal client_secret not flagged: %v", st)
	}
	missing := creds.Binding{Host: "api.example.com", OAuth2: &creds.OAuth2{TokenURL: "http://auth.example.com/token", ClientID: "c", ClientSecret: "${DOCTOR_APP_ID}"}}
	if st := brokerStatuses(auditCredentials(dir, &config.Config{Credentials: []creds.Binding{missing}})); !strings.Contains(st["FAIL"], "https") {
		t.Fatalf("plain-http token_url not flagged: %v", st)
	}
}

// `ovara env` gives the agent a GITHUB_TOKEN placeholder for a GitHub App
// binding, not the broker's own inputs.
func TestBindingKeysGitHubApp(t *testing.T) {
	got := bindingKeys([]creds.Binding{{Host: "api.github.com", GitHubApp: &creds.GitHubApp{AppID: "${GH_APP_ID}", PrivateKey: "${GH_APP_KEY}"}}})
	if strings.Join(got, ",") != "GITHUB_TOKEN" {
		t.Fatalf("keys %v, want GITHUB_TOKEN only", got)
	}
}

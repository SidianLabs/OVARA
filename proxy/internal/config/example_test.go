package config

import (
	"testing"

	"ovara.proxy/internal/creds"
)

// The example etc/proxy.json parses, its brokered bindings are read as
// such, and with no variables set every binding is skipped, not refused.
func TestExampleProxyConfigLoads(t *testing.T) {
	cfg, err := Load("../../etc/proxy.json")
	if err != nil {
		t.Fatal(err)
	}
	var gh, oauth bool
	for _, b := range cfg.Credentials {
		gh = gh || (b.GitHubApp != nil && b.GitHubApp.InstallationID != "")
		oauth = oauth || (b.OAuth2 != nil && b.OAuth2.TokenURL != "")
	}
	if !gh || !oauth {
		t.Fatalf("example lost its broker bindings (github_app %v, oauth2 %v)", gh, oauth)
	}
	for _, v := range []string{"GH_APP_ID", "GH_APP_INSTALLATION_ID", "GH_APP_KEY_FILE", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SLACK_TOKEN", "EXAMPLE_CLIENT_ID", "EXAMPLE_CLIENT_SECRET"} {
		t.Setenv(v, "")
	}
	out, skipped, err := creds.LoadReport(cfg.Credentials)
	if err != nil || len(out) != 0 || len(skipped) != len(cfg.Credentials) {
		t.Fatalf("out %d skipped %d err %v", len(out), len(skipped), err)
	}
}

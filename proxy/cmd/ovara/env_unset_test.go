package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// CR-10: other secret-looking variables are unset unless -keep-env.
func TestSecretEnvNames(t *testing.T) {
	env := []string{
		"PATH=/bin", "HOME=/root", "GITHUB_TOKEN=placeholder-is-set-by-ovara",
		"AWS_SECRET_ACCESS_KEY=x", "AWS_REGION=eu", "MY_SERVICE_PASSWORD=x", "NPM_TOKEN=x",
		"GOOGLE_APPLICATION_CREDENTIALS=/k.json", "GH_ENTERPRISE_TOKEN=x", "STRIPE_API_KEY=x",
		"AZURE_CLIENT_SECRET=x", "BAD;NAME_TOKEN=x", "TERM=xterm",
	}
	got := secretEnvNames(env, map[string]bool{"GITHUB_TOKEN": true})
	want := []string{"AWS_REGION", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GH_ENTERPRISE_TOKEN",
		"GOOGLE_APPLICATION_CREDENTIALS", "MY_SERVICE_PASSWORD", "NPM_TOKEN", "STRIPE_API_KEY"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	for sh, line := range map[string]string{
		"bash":       "unset NPM_TOKEN",
		"powershell": "Remove-Item Env:NPM_TOKEN -ErrorAction SilentlyContinue",
		"cmd":        `set "NPM_TOKEN="`,
	} {
		var b bytes.Buffer
		if err := writeUnsets(&b, sh, []string{"NPM_TOKEN"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), line) || !strings.Contains(b.String(), "-keep-env") {
			t.Errorf("%s:\n%s", sh, b.String())
		}
	}
}

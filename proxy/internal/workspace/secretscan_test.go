package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Fake keys in the formats the scan knows, put together at run time so
// this file does not itself read as holding keys.
var (
	fakeAWS    = "AK" + "IA" + "Q7XR2M4KZP9WLB3D"
	fakeGitHub = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
	fakeGitLab = "gl" + "pat-" + "Zq8Lw2Xr5Tn9Vb3Mk6Hd"
	fakeSlack  = "xo" + "xb-" + "1234567890-AbCdEfGhIjKl"
	fakeRandom = "Xk29dLm3Qp8Rt5Vw7Yz1Bn4C"
	fakePEM    = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n"
)

func TestScanSecret(t *testing.T) {
	found := map[string]string{
		"aws key":         "region = us-east-1\nkey = " + fakeAWS + "\n",
		"aws secret":      "[default]\naws_secret_access_key = " + strings.Repeat("aB3/", 10) + "\n",
		"github":          "token: " + fakeGitHub,
		"gitlab":          "CI_TOKEN " + fakeGitLab,
		"slack":           "bot " + fakeSlack,
		"pem":             fakePEM,
		"npmrc":           "//registry.npmjs.org/:_authToken=npm_" + fakeRandom + "\n",
		"netrc":           "machine api.example.com login me password hunter2\n",
		"git credentials": "https://alice:" + fakeGitHub + "@github.com\n",
		"service account": `{"type": "service_account", "project_id": "p", "private_key": "x"}`,
		"refresh token":   `{"client_id": "a", "refresh_token": "1//0g` + fakeRandom + `", "type": "authorized_user"}`,
		"azure":           "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=" + strings.Repeat("Ab3+", 11) + "==",
		"kubeconfig":      "apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    token: pass1234\n",
		"env":             "DEBUG=1\nSTRIPE_SECRET_KEY=sk_live_" + fakeRandom + "\n",
		"yaml var":        "service:\n  api_token: \"" + fakeRandom + "\"\n",
	}
	for name, content := range found {
		if what := scanSecret([]byte(content)); what == "" {
			t.Errorf("%s: not found", name)
		}
	}
	clean := map[string]string{
		"readme":         "# Project\n\nSet API_KEY in your environment. See https://example.com/docs.\n",
		"placeholder":    "API_KEY=your-api-key-here\nTOKEN=${GITHUB_TOKEN}\nSECRET=<secret>\n",
		"npmrc env":      "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
		"code":           "cache_key = \"user_profile_v2_settings\"\nmonkey = make_monkey(3)\n",
		"package lock":   `{"node_modules/js-tokens": {"version": "4.0.0", "integrity": "sha512-RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ=="}}`,
		"url no secret":  "git clone https://github.com/a/b.git\nhttp://user:pass@localhost:8080\n",
		"not kubeconfig": "token: pass1234\n",
		"go.sum":         "golang.org/x/sys v0.20.0 h1:abcdefghijklmnopqrstuvwxyz0123456789ABCD=\n",
	}
	for name, content := range clean {
		if what := scanSecret([]byte(content)); what != "" {
			t.Errorf("%s: flagged as %s", name, what)
		}
	}
}

// A key under a harmless name is left out of the copy and listed; the
// project's other files are there.
func TestCreate_LeavesOutSecretsByContent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	p := project(t)
	write(t, filepath.Join(p, "docs/notes.txt"), "the deploy key: "+fakeAWS+"\n") // untracked
	write(t, filepath.Join(p, "src/settings.yml"), "db:\n  password: \""+fakeRandom+"\"\n")
	write(t, filepath.Join(p, "src/ok.yml"), "db:\n  host: localhost\n")
	write(t, filepath.Join(p, "sub/.git-credentials"), "https://a:b@c\n")
	git(t, p, "add", "src", "sub")
	git(t, p, "commit", "--quiet", "-m", "settings")
	dir := filepath.Join(t.TempDir(), "work")
	ws, err := Create(p, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"docs/notes.txt", "src/settings.yml"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			t.Errorf("%s is in the workspace", rel)
		}
		if ws.SecretContent[rel] == "" {
			t.Errorf("%s not listed as left out: %v", rel, ws.SecretContent)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sub/.git-credentials")); err == nil {
		t.Error(".git-credentials is in the workspace")
	}
	for _, rel := range []string{"src/ok.yml", "README.md", "app.py"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("%s missing: %v", rel, err)
		}
	}
	// the record keeps the list
	ws2, err := Load(dir)
	if err != nil || ws2.SecretContent["src/settings.yml"] == "" {
		t.Errorf("record: %v %v", ws2, err)
	}
}

func TestScrubGitConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".git/config"), "[remote \"origin\"]\n\turl = https://bob:"+fakeGitHub+"@github.com/a/b.git\n\tpushurl = ssh://git@host/x\n[remote \"m\"]\n\turl = https://mirror.example/b.git\n")
	changed, err := scrubGitConfig(dir)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".git/config"))
	got := string(b)
	if strings.Contains(got, fakeGitHub) || strings.Contains(got, "bob") || strings.Contains(got, "git@") {
		t.Errorf("credentials left:\n%s", got)
	}
	if !strings.Contains(got, "url = https://github.com/a/b.git") || !strings.Contains(got, "https://mirror.example/b.git") {
		t.Errorf("URLs damaged:\n%s", got)
	}
	if changed, _ := scrubGitConfig(dir); changed {
		t.Error("a clean config was changed")
	}
}

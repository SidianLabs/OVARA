//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/gateway"
)

// The gate asks policy about the normalised command but shows the person
// the command as it was run; the command the person gave the box is not
// paused, the agent's own commands are.
func TestCommandGate_PolicyLineAndLaunch(t *testing.T) {
	var resources, shown []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime/check" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Resource string `json:"resource"`
			Metadata struct {
				Context map[string]string `json:"proxy_context"`
			} `json:"metadata"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		resources = append(resources, body.Resource)
		shown = append(shown, body.Metadata.Context["command"])
		_ = json.NewEncoder(w).Encode(map[string]string{"decision": "escalate", "decision_id": "d1"})
	}))
	defer srv.Close()
	launch := []string{"agent", "--dangerously-skip-permissions"}
	g := newCommandGate(gateway.New(srv.URL, "", "dev"), t.TempDir(), time.Millisecond, true, launch, nil)
	if v := g.decide(boxgate.Exec{Argv: launch}); v != boxgate.Allow {
		t.Fatal("the command the person gave the box was paused")
	}
	// the same command started again by the agent is the agent's: paused,
	// and refused here because no approval can be opened
	if v := g.decide(boxgate.Exec{Argv: launch}); v != boxgate.Deny {
		t.Fatal("the agent's own command was let through")
	}
	g.decide(boxgate.Exec{Argv: []string{"/bin/rm", "-r", "-f", "/work"}})
	if got := resources[len(resources)-1]; got != "shell:rm -rf /work" {
		t.Errorf("policy saw %q", got)
	}
	if got := shown[len(shown)-1]; got != "rm -r -f /work" {
		t.Errorf("the person sees %q, want the command as run", got)
	}
}

func TestCheckMounts(t *testing.T) {
	tmp := t.TempDir()
	tools := filepath.Join(tmp, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	ovaraDir := filepath.Join(tmp, "deploy")
	if err := os.MkdirAll(filepath.Join(ovaraDir, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	ok := []string{
		tools + ":/opt/tools",
		tools + ":/tmp/tools", // inside the box's own /tmp is fine
		"/usr/local:/opt/host-local",
	}
	for _, m := range ok {
		if err := checkMounts([]string{m}, ovaraDir); err != nil {
			t.Errorf("%s refused: %v", m, err)
		}
	}
	refused := map[string]string{
		"/:/host":                              "whole host",
		"/etc:/x":                              "inside /etc",
		"/etc/ssl:/x":                          "inside /etc",
		"/root:/x":                             "inside /root",
		"/var:/x":                              "contains",
		ovaraDir + ":/x":                       "inside",
		filepath.Join(ovaraDir, "var") + ":/x": "inside",
		tools + ":/work":                       "clashes",
		tools + ":/work/sub":                   "clashes",
		tools + ":/run/ovara":                  "clashes",
		tools + ":/opt":                        "clashes", // would cover /opt/ovara
		tools + ":/":                           "clashes",
		tools + ":relative":                    "absolute",
		tools:                                  "absolute",
		filepath.Join(tmp, "missing") + ":/x":  "no such file",
	}
	for m, want := range refused {
		err := checkMounts([]string{m}, ovaraDir)
		if err == nil {
			t.Errorf("%s accepted", m)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want it to mention %q)", m, err, want)
		}
	}
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"PATH=/a", "HOME=/h"}, []string{"PATH=/b", "X=1"})
	want := "PATH=/b HOME=/h X=1"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

func TestDefaultBoxImage(t *testing.T) {
	saved := boxImage
	defer func() { boxImage = saved }()
	boxImage = ""
	if got := defaultBoxImage(); got != boxDefaultImage {
		t.Fatalf("dev build: %q", got)
	}
	boxImage = "ghcr.io/sidianlabs/ovara-box@sha256:abc"
	if got := defaultBoxImage(); got != boxImage {
		t.Fatalf("release build: %q", got)
	}
}

func TestAgentImage(t *testing.T) {
	savedImg, savedVer := boxImage, version
	defer func() { boxImage, version = savedImg, savedVer }()
	boxImage, version = "", "dev"
	if got, err := agentImage("codex"); err != nil || got != "ovara-box-codex" {
		t.Fatalf("dev: %q %v", got, err)
	}
	boxImage, version = "ghcr.io/sidianlabs/ovara-box@sha256:abc", "v0.10.0"
	if got, err := agentImage("claude"); err != nil || got != "ghcr.io/sidianlabs/ovara-box-claude:v0.10.0" {
		t.Fatalf("release: %q %v", got, err)
	}
	if _, err := agentImage("cursor"); err == nil {
		t.Fatal("unknown agent accepted")
	}
}

// A missing -agent-image image is built from box/agents on top of the box
// image; building box/ under the agent's name would leave the agent out.
func TestImageNotFoundSaysHowToBuildIt(t *testing.T) {
	if msg := imageNotFound("ovara-box-codex").Error(); !strings.Contains(msg, "`docker build -t ovara-box box/` then `docker build --build-arg AGENT=codex -t ovara-box-codex box/agents`") {
		t.Fatalf("agent image: %s", msg)
	}
	for _, image := range []string{"ovara-box", "ovara-box-cursor", "mybox"} {
		if msg := imageNotFound(image).Error(); !strings.Contains(msg, "`docker build -t "+image+" box/`") {
			t.Fatalf("%s: %s", image, msg)
		}
	}
}

// checkTier1Tools names the missing command (ip) instead of letting the
// boundary fail mid-setup and `ovara run` only time out.
func TestCheckTier1Tools(t *testing.T) {
	saved := os.Getenv("PATH")
	defer os.Setenv("PATH", saved)
	os.Setenv("PATH", t.TempDir()) // nothing on PATH
	err := checkTier1Tools()
	if err == nil || !strings.Contains(err.Error(), "`ip`") {
		t.Fatalf("empty PATH: want an error naming ip, got %v", err)
	}
}

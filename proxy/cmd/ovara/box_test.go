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
		json.NewDecoder(r.Body).Decode(&body)
		resources = append(resources, body.Resource)
		shown = append(shown, body.Metadata.Context["command"])
		json.NewEncoder(w).Encode(map[string]string{"decision": "escalate", "decision_id": "d1"})
	}))
	defer srv.Close()
	launch := []string{"agent", "--dangerously-skip-permissions"}
	g := newCommandGate(gateway.New(srv.URL, "", "dev"), t.TempDir(), time.Millisecond, true, launch)
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

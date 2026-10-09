//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

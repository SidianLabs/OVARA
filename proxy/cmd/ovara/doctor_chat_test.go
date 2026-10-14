package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"ovara.proxy/internal/config"
)

func TestDoctor_Chat(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	if auditChat(dir, cfg) != nil {
		t.Fatal("nothing configured, something said")
	}
	cfg.Chat = &config.Chat{Slack: &config.SlackChat{Channel: "C0TEST", TokenFile: "var/slack.token"}}
	if st := statuses(auditChat(dir, cfg)); st["chat token"] != checkFail || st["chat approvals"] != checkWarn {
		t.Fatalf("no token file, nobody allowed: %v", st)
	}
	if err := os.MkdirAll(filepath.Join(dir, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "var/slack.token"), []byte("xoxb-1\n"), 0o644); err != nil { //nolint:gosec // the test wants it readable
		t.Fatal(err)
	}
	st := statuses(auditChat(dir, cfg))
	if runtime.GOOS != "windows" && st["chat token"] != checkWarn {
		t.Fatalf("world-readable token: %v", st)
	}
	if err := os.Chmod(filepath.Join(dir, "var/slack.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Chat.Slack.AllowedUsers = []string{"U1"}
	if st := statuses(auditChat(dir, cfg)); st["chat token"] != checkPass || st["chat approvals"] != checkPass {
		t.Fatalf("set up: %v", st)
	}
	cfg.Chat.Slack = &config.SlackChat{Channel: "C0TEST", TokenEnv: "OVARA_SLACK_TOKEN", AllowedUsers: []string{"U1"}}
	if st := statuses(auditChat(dir, cfg)); st["chat token"] != checkPass {
		t.Fatalf("token from the environment: %v", st)
	}
}

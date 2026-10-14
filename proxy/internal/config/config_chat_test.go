package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_ChatSlack(t *testing.T) {
	dir := t.TempDir()
	write := func(chat string) (*Config, error) {
		p := filepath.Join(dir, "proxy.json")
		if err := os.WriteFile(p, []byte(`{"listen_addr":"127.0.0.1:9443","gateway_url":"http://127.0.0.1:8080","agent_token":"t","chat":`+chat+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(p)
	}
	if _, err := write(`{"slack":{"channel":"#approvals"}}`); err == nil || !strings.Contains(err.Error(), "channel's ID") {
		t.Fatalf("a channel name: %v", err)
	}
	if _, err := write(`{"slack":{"channel":"C0123ABCD","allowed_users":["bob"]}}`); err == nil || !strings.Contains(err.Error(), "user ID") {
		t.Fatalf("a user name: %v", err)
	}
	if _, err := write(`{}`); err == nil || !strings.Contains(err.Error(), "chat.slack") {
		t.Fatalf("no provider: %v", err)
	}
	c, err := write(`{"slack":{"channel":"C0123ABCD","allowed_users":["U0AAAAAAA","W0BBBBBBB"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Chat.Slack; s.TokenFile != "var/slack.token" || s.PollSec != 4 || len(s.AllowedUsers) != 2 {
		t.Fatalf("defaults: %+v", s)
	}
	c, err = write(`{"slack":{"channel":"G0123ABCD","token_env":"OVARA_SLACK_TOKEN","poll_sec":10}}`)
	if err != nil || c.Chat.Slack.TokenFile != "" || c.Chat.Slack.PollSec != 10 {
		t.Fatalf("token from the environment: %v %+v", err, c.Chat.Slack)
	}
}

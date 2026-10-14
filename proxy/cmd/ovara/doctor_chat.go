package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"ovara.proxy/internal/config"
)

// auditChat checks the chat approvals proxy.json sets up: the token is
// where it should be and nobody else's, and someone may actually decide.
func auditChat(dir string, cfg *config.Config) []check {
	if cfg.Chat == nil || cfg.Chat.Slack == nil {
		return nil
	}
	s := cfg.Chat.Slack
	var out []check
	switch {
	case s.TokenEnv != "":
		out = append(out, check{"chat token", checkPass, fmt.Sprintf("Slack token comes from $%s when ovara run starts", s.TokenEnv)})
	default:
		path := filepath.Join(dir, s.TokenFile)
		st, err := os.Stat(path)
		switch {
		case err != nil:
			out = append(out, check{"chat token", checkFail, "Slack token: " + err.Error() + " (a bot token, xoxb-…, on one line; ovara run will not start)"})
		case runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0:
			out = append(out, check{"chat token", checkWarn, fmt.Sprintf("Slack token %s is readable by others (chmod 600)", path)})
		default:
			out = append(out, check{"chat token", checkPass, "Slack token in " + path + ", owner-only"})
		}
	}
	if len(s.AllowedUsers) == 0 {
		out = append(out, check{"chat approvals", checkWarn, "Slack channel " + s.Channel + " is told about paused requests but nobody can decide there: chat.slack.allowed_users is empty"})
	} else {
		out = append(out, check{"chat approvals", checkPass, fmt.Sprintf("Slack channel %s; %d person(s) may decide there and see what the approval page shows", s.Channel, len(s.AllowedUsers))})
	}
	return out
}

package main

// Approvals from chat, one provider: Slack. `ovara run` posts every paused
// request to a channel as `ovara watch` would print it, and takes the
// answer from a reply in that thread, but only from the people named in
// chat.slack.allowed_users: a channel can be wide, the right to decide is
// not. Replies from anyone else, and from bots, change nothing. Slack is
// polled; nothing listens for Slack, so this works from a laptop or a CI
// job with no address reachable from the internet.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"ovara.proxy/internal/config"
)

const slackAPI = "https://slack.com/api"

// The two words a thread reply must start with to decide anything; what
// follows a colon is the reason. Nothing looser: a thread is also where
// people talk about the request.
var slackDecisionRe = regexp.MustCompile(`(?i)^(approve|approved|deny|denied|reject|rejected)\b[\s:.,-]*(.*)$`)

type slackBridge struct {
	admin   *adminClient
	hc      *http.Client
	api     string
	token   string
	channel string
	allowed map[string]bool
	every   time.Duration
	logf    func(format string, args ...any)

	mu      sync.Mutex
	threads map[string]*slackThread // approval id → the thread that shows it
	done    map[string]bool         // decided or closed: never posted again
	lastErr string
}

type slackThread struct {
	ts     string // the message's ts, which names the thread
	seen   string // the newest reply already read
	warned bool   // someone not allowed was told once
}

func newSlackBridge(cfg *config.Config, dir string) (*slackBridge, error) {
	s := cfg.Chat.Slack
	admin, err := newAdminClient(dir)
	if err != nil {
		return nil, err
	}
	token, err := slackToken(dir, s)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(s.AllowedUsers))
	for _, u := range s.AllowedUsers {
		allowed[u] = true
	}
	return &slackBridge{
		admin: admin, hc: &http.Client{Timeout: 20 * time.Second, Transport: chatTransport(cfg)},
		api: slackAPI, token: token, channel: s.Channel, allowed: allowed,
		every: time.Duration(s.PollSec) * time.Second, logf: log.Printf,
		threads: map[string]*slackThread{}, done: map[string]bool{},
	}, nil
}

// slackToken is the bot token, from the variable or the file proxy.json
// names. ovara run reads it; the agent never gets it (ovara env empties
// secret-looking variables, and the file is Ovara's).
func slackToken(dir string, s *config.SlackChat) (string, error) {
	if s.TokenEnv != "" {
		if v := strings.TrimSpace(os.Getenv(s.TokenEnv)); v != "" {
			return v, nil
		}
		if s.TokenFile == "" {
			return "", fmt.Errorf("the Slack token: %s is not set (chat.slack.token_env)", s.TokenEnv)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, s.TokenFile)) //nolint:gosec // the operator's own file, named in proxy.json
	if err != nil {
		return "", fmt.Errorf("the Slack token: %w (a bot token, xoxb-…, on one line in %s, or chat.slack.token_env)", err, s.TokenFile)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("the Slack token file %s is empty", s.TokenFile)
	}
	return tok, nil
}

// chatTransport is how ovara run reaches the chat service: directly, or
// through the upstream proxy and with the extra CA that proxy.json names
// for Ovara's own outbound side (never through the agent's proxy).
func chatTransport(cfg *config.Config) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.UpstreamProxy != "" {
		if u, err := url.Parse(cfg.UpstreamProxy); err == nil {
			t.Proxy = http.ProxyURL(u)
		}
	}
	if cfg.UpstreamCABundle != "" {
		if pem, err := os.ReadFile(cfg.UpstreamCABundle); err == nil { //nolint:gosec // the operator's own CA file
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
			t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	return t
}

func (b *slackBridge) describe() string {
	s := "approvals also go to Slack channel " + b.channel
	if len(b.allowed) == 0 {
		return s + "; nobody is listed in chat.slack.allowed_users, so the channel is told but cannot decide"
	}
	return s + fmt.Sprintf("; %d listed person(s) can answer in the thread", len(b.allowed))
}

// start polls until stop is called.
func (b *slackBridge) start() (stop func()) {
	stopc, donec := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(donec)
		for {
			b.tick()
			select {
			case <-stopc:
				return
			case <-time.After(b.every):
			}
		}
	}()
	return func() { close(stopc); <-donec }
}

// tick is one round: requests that ended elsewhere are closed in their
// thread, new paused requests are posted, open threads are read for an
// answer. An error is logged once per change and the next round retries.
func (b *slackBridge) tick() {
	list, err := b.admin.pending()
	if err != nil {
		b.report("pending approvals: " + err.Error())
		return
	}
	open := make(map[string]bool, len(list))
	for _, a := range list {
		open[a.ApprovalID] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, th := range b.threads {
		if !open[id] {
			b.reply(th.ts, "This request ended without an answer here: approved or denied elsewhere, expired, or the agent stopped.")
			delete(b.threads, id)
			b.done[id] = true
		}
	}
	for _, a := range list {
		if b.done[a.ApprovalID] || b.threads[a.ApprovalID] != nil || b.admin.stale(a) {
			continue
		}
		ts, err := b.post(approvalText(a), "")
		if err != nil {
			b.report("posting to Slack: " + err.Error())
			return
		}
		b.threads[a.ApprovalID] = &slackThread{ts: ts}
	}
	for id, th := range b.threads {
		if err := b.answers(id, th); err != nil {
			b.report("reading Slack replies: " + err.Error())
			return
		}
	}
	b.report("")
}

// answers reads a thread's new replies and acts on the first decision from
// an allowed person.
func (b *slackBridge) answers(id string, th *slackThread) error {
	msgs, err := b.replies(th.ts, th.seen)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.TS == th.ts || m.TS <= th.seen || m.BotID != "" || m.User == "" {
			continue
		}
		th.seen = m.TS
		approve, reason, ok := slackDecision(m.Text)
		if !ok {
			continue
		}
		if !b.allowed[m.User] {
			if !th.warned {
				th.warned = true
				b.reply(th.ts, fmt.Sprintf("<@%s> only the people listed in chat.slack.allowed_users can decide this; nothing happened.", m.User))
			}
			continue
		}
		if err := b.admin.resolve(id, approve, "slack:"+m.User, reason); err != nil {
			b.reply(th.ts, "Could not record that: "+slackEscape(err.Error()))
			continue
		}
		verdict := "✓ approved"
		if !approve {
			verdict = "✗ denied"
		}
		if reason != "" {
			reason = ": " + slackEscape(reason)
		}
		b.reply(th.ts, fmt.Sprintf("%s by <@%s>%s", verdict, m.User, reason))
		delete(b.threads, id)
		b.done[id] = true
		return nil
	}
	return nil
}

// report logs an error when it changes, and silence when it clears.
func (b *slackBridge) report(msg string) {
	if msg == b.lastErr {
		return
	}
	b.lastErr = msg
	if msg != "" {
		b.logf("slack approvals: %s", msg)
	}
}

// slackDecision reads a reply: approve/deny as its first word, a reason
// after a colon. Anything else is talk.
func slackDecision(text string) (approve bool, reason string, ok bool) {
	m := slackDecisionRe.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return false, "", false
	}
	return strings.HasPrefix(strings.ToLower(m[1]), "approve"), strings.TrimSpace(m[2]), true
}

// approvalText is the message for a paused request: what ovara watch
// prints, in a code block, and how to answer.
func approvalText(a pendingApproval) string {
	var buf bytes.Buffer
	printApproval(&buf, a)
	return "Approval needed: " + slackEscape(describe(a.Resource)) + "\n```\n" + slackEscape(buf.String()) +
		"```\nReply in this thread with *approve* or *deny*, a reason after a colon if you like (`deny: not from CI`). Only the people in chat.slack.allowed_users decide."
}

// slackEscape is the escaping Slack message text needs.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

type slackMsg struct {
	TS    string `json:"ts"`
	User  string `json:"user"`
	BotID string `json:"bot_id"`
	Text  string `json:"text"`
}

func (b *slackBridge) post(text, threadTS string) (string, error) {
	body := map[string]any{"channel": b.channel, "text": text, "unfurl_links": false, "unfurl_media": false}
	if threadTS != "" {
		body["thread_ts"] = threadTS
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	if err := b.call(http.MethodPost, "chat.postMessage", body, &out); err != nil {
		return "", err
	}
	if !out.OK {
		return "", fmt.Errorf("chat.postMessage: %s", slackErrorHint(out.Error))
	}
	return out.TS, nil
}

func (b *slackBridge) reply(threadTS, text string) {
	if _, err := b.post(text, threadTS); err != nil {
		b.report("replying in Slack: " + err.Error())
	}
}

func (b *slackBridge) replies(threadTS, after string) ([]slackMsg, error) {
	q := url.Values{"channel": {b.channel}, "ts": {threadTS}, "limit": {"100"}}
	if after != "" {
		q.Set("oldest", after)
		q.Set("inclusive", "false")
	}
	var out struct {
		OK       bool       `json:"ok"`
		Error    string     `json:"error"`
		Messages []slackMsg `json:"messages"`
	}
	if err := b.call(http.MethodGet, "conversations.replies?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("conversations.replies: %s", slackErrorHint(out.Error))
	}
	return out.Messages, nil
}

func (b *slackBridge) call(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.api+"/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("Slack asks to slow down (429, Retry-After %s)", resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Slack said %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// slackErrorHint says what to do about the Slack errors a setup usually hits.
func slackErrorHint(code string) string {
	switch code {
	case "not_in_channel":
		return code + " (invite the bot to the channel: /invite @its-name)"
	case "channel_not_found":
		return code + " (chat.slack.channel must be the channel's ID, from its details, not its name)"
	case "invalid_auth", "not_authed", "token_revoked", "account_inactive":
		return code + " (the bot token is wrong or revoked)"
	case "missing_scope":
		return code + " (the app needs chat:write, and channels:history or groups:history)"
	}
	return code
}

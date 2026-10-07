package main

// Human-facing approval commands. An agent that hits a risky action is
// paused by the proxy and an approval is opened on the gateway; these
// commands are how the person in charge sees it and answers.
//
//	ovara watch        interactive: prompts for each request as it arrives
//	ovara approvals    list what is waiting
//	ovara approve <id> allow it
//	ovara deny <id>    refuse it

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// adminClient talks to the local gateway as the operator.
type adminClient struct {
	base  string
	token string
	hc    *http.Client
}

type pendingApproval struct {
	ApprovalID string    `json:"approval_id"`
	ActionType string    `json:"action_type"`
	Resource   string    `json:"resource"`
	AgentID    string    `json:"agent_id"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
}

// newAdminClient reads the deployment's config.json for the gateway
// address and operator token — the same file `ovara init` wrote.
func newAdminClient(dir string) (*adminClient, error) {
	path := filepath.Join(dir, "config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w (run `ovara init %s` first, or pass -dir)", path, err, dir)
	}
	var cfg struct {
		Port   string   `json:"server_port"`
		Addr   string   `json:"listen_addr"`
		Tokens []string `json:"operator_tokens"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	if len(cfg.Tokens) == 0 {
		return nil, fmt.Errorf("config.json has no operator_tokens — approving requires the operator token")
	}
	host := cfg.Addr
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return &adminClient{
		base:  "http://" + host + ":" + cfg.Port,
		token: cfg.Tokens[0],
		hc:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *adminClient) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the gateway at %s — is `ovara run` running? (%v)", c.base, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gateway said %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *adminClient) pending() ([]pendingApproval, error) {
	var resp struct {
		Approvals []pendingApproval `json:"approvals"`
	}
	if err := c.do("GET", "/v1/approval/pending", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Approvals, nil
}

func (c *adminClient) resolve(id string, approve bool, who, reason string) error {
	verb := "deny"
	if approve {
		verb = "approve"
	}
	body := map[string]string{"resolved_by": who}
	if reason != "" {
		body["reason"] = reason
	}
	return c.do("POST", "/v1/approval/"+url.PathEscape(id)+"/"+verb, body, nil)
}

// describe turns a policy resource string into one plain-English line.
// Resources look like "POST https://github.com/org/repo.git/git-receive-pack refs/heads/main".
func describe(resource string) string {
	method, rest, ok := strings.Cut(resource, " ")
	if !ok {
		return resource
	}
	target, extra, _ := strings.Cut(rest, " ")
	if strings.Contains(target, "git-receive-pack") {
		repo := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
		repo, _, _ = strings.Cut(repo, "/git-receive-pack")
		repo = strings.TrimSuffix(repo, ".git")
		what := "push code"
		if extra != "" && !strings.HasPrefix(extra, "git-receive-pack") {
			what = "push to " + strings.ReplaceAll(extra, ",", ", ")
		}
		return fmt.Sprintf("%s on %s", what, repo)
	}
	switch method {
	case "GET", "HEAD":
		return "read " + target
	case "POST":
		return "send data to " + target
	case "PUT", "PATCH":
		return "modify " + target
	case "DELETE":
		return "DELETE " + target
	}
	return method + " " + target
}

// whoAmI labels the human resolving an approval (display suffix only —
// the gateway derives the real identity from the operator token).
func whoAmI() string {
	for _, k := range []string{"USER", "USERNAME"} {
		if u := os.Getenv(k); u != "" {
			return u
		}
	}
	return "operator"
}

func dirFlag(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote config.json)")
	return fs, dir
}

func printApproval(w io.Writer, a pendingApproval) {
	age := time.Duration(0)
	if !a.CreatedAt.IsZero() {
		age = time.Since(a.CreatedAt).Round(time.Second)
	}
	fmt.Fprintln(w, "┌─ approval needed ─────────────────────────────────────")
	fmt.Fprintf(w, "│ agent wants to: %s\n", describe(a.Resource))
	fmt.Fprintf(w, "│ raw request:    %s\n", a.Resource)
	if a.AgentID != "" {
		fmt.Fprintf(w, "│ agent:          %s\n", a.AgentID)
	}
	fmt.Fprintf(w, "│ waiting:        %s   id: %s\n", age, a.ApprovalID)
	fmt.Fprintln(w, "└───────────────────────────────────────────────────────")
}

func cmdApprovals(args []string) error {
	fs, dir := dirFlag("approvals")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newAdminClient(*dir)
	if err != nil {
		return err
	}
	list, err := c.pending()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("nothing waiting for approval.")
		return nil
	}
	for _, a := range list {
		printApproval(os.Stdout, a)
	}
	fmt.Printf("\n%d waiting.  ovara approve <id>   or   ovara deny <id>   (or run `ovara watch`)\n", len(list))
	return nil
}

func cmdResolve(approve bool, args []string) error {
	name := "deny"
	if approve {
		name = "approve"
	}
	fs, dir := dirFlag(name)
	reason := fs.String("reason", "", "optional reason, recorded in the audit trail")
	// Accept the id before or after the flags: `ovara approve <id> -dir x`.
	var id string
	var rest []string
	for _, a := range args {
		if id == "" && !strings.HasPrefix(a, "-") {
			id = a
			continue
		}
		rest = append(rest, a)
	}
	if id == "" {
		return fmt.Errorf("usage: ovara %s <approval-id> [-dir .] [-reason ...]", name)
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	c, err := newAdminClient(*dir)
	if err != nil {
		return err
	}
	if err := c.resolve(id, approve, whoAmI(), *reason); err != nil {
		return err
	}
	if approve {
		fmt.Printf("approved %s — the agent's request will now go through.\n", id)
	} else {
		fmt.Printf("denied %s — the agent's request is blocked.\n", id)
	}
	return nil
}

// cmdWatch prompts for each pending approval as it arrives.
func cmdWatch(args []string) error {
	fs, dir := dirFlag("watch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newAdminClient(*dir)
	if err != nil {
		return err
	}
	return watchLoop(c, os.Stdin, os.Stdout, 2*time.Second, nil)
}

// watchLoop polls for pending approvals and asks on in/out for each. A
// closed stop channel ends the loop (tests); so does closed input.
func watchLoop(c *adminClient, in io.Reader, out io.Writer, every time.Duration, stop <-chan struct{}) error {
	rd := bufio.NewReader(in)
	fmt.Fprintln(out, "watching for agent requests that need your approval… (Ctrl+C to quit)")
	seen := map[string]bool{}
	for {
		list, err := c.pending()
		if err != nil {
			return err
		}
		for _, a := range list {
			if seen[a.ApprovalID] {
				continue
			}
			seen[a.ApprovalID] = true
			fmt.Fprintln(out)
			printApproval(out, a)
			if !askAndResolve(c, a, rd, out) {
				return nil // input closed
			}
		}
		select {
		case <-stop:
			return nil
		case <-time.After(every):
		}
	}
}

// askAndResolve prompts until it gets a usable answer. Returns false when
// the input stream is closed.
func askAndResolve(c *adminClient, a pendingApproval, rd *bufio.Reader, out io.Writer) bool {
	for {
		fmt.Fprint(out, "  [a]pprove  [d]eny  [s]kip > ")
		line, err := rd.ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		if err != nil && ans == "" {
			return false
		}
		switch ans {
		case "a", "approve", "y", "yes":
			if e := c.resolve(a.ApprovalID, true, whoAmI(), ""); e != nil {
				fmt.Fprintln(out, "  could not approve:", e)
			} else {
				fmt.Fprintln(out, "  ✓ approved")
			}
		case "d", "deny", "n", "no":
			if e := c.resolve(a.ApprovalID, false, whoAmI(), "denied from ovara watch"); e != nil {
				fmt.Fprintln(out, "  could not deny:", e)
			} else {
				fmt.Fprintln(out, "  ✗ denied")
			}
		case "s", "skip", "":
			fmt.Fprintln(out, "  skipped (still pending — use `ovara approve/deny` later)")
		default:
			continue
		}
		return true
	}
}

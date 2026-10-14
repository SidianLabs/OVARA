package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// `ovara policy suggest`: the rules a strict policy would need for what the
// agent actually did, read from the verified receipts. It is how an
// observe run (reads free, writes refused) becomes a policy, and how a
// strict run's held requests become rules:
//
//   - one read allow (GET and HEAD) per public host the agent read without
//     a rule naming it: a read let through by an open-read rule, or held
//     without any rule;
//   - one exact write allow per write refused by a profile's catch-all or
//     held without any rule, for the person to accept or not.
//
// Never a wildcard write, never a host a rule already names, never a read
// a deny rule refused, never plain http, never an IP literal. The rules go
// to stdout as JSON, the summary to stderr.

const suggestedMarker = "[suggested"

type suggestion struct {
	resource string // a host (reads) or "METHOD https://host/path" (a write)
	count    int
	first    time.Time
	write    bool
}

func cmdPolicySuggest(args []string) error {
	fs := flag.NewFlagSet("policy suggest", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	agent := fs.String("agent", "", "only this named agent's requests")
	since := fs.Duration("since", 0, "only requests in the last DURATION, e.g. 2h (default: all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(*dir, "proxy.json"))
	if err != nil {
		return fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", *dir, err)
	}
	rules, summary, err := suggestRules(inDir(*dir, cfg.ReceiptsFile), inDir(*dir, cfg.PubKeyFile), *agent, *since, time.Now())
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, summary)
	fmt.Fprintf(os.Stderr, "paste the rules you accept into the \"rules\" of %s; the gateway reloads it on its own\n", filepath.Join(*dir, "policy.json"))
	return nil
}

// suggestRules reads and verifies the chain and returns the rules and a
// summary line. A chain that does not verify suggests nothing.
func suggestRules(receiptsFile, pubFile, agent string, since time.Duration, now time.Time) ([]map[string]any, string, error) {
	all, err := scanReceipts(receiptsFile)
	if err != nil {
		return nil, "", err
	}
	if len(all) > 0 {
		ring, err := receipts.LoadKeyRing(pubFile)
		if err != nil {
			return nil, "", err
		}
		res, _ := receipts.VerifyWithAnchorsKeys(receiptsFile, receipts.AnchorPathFor(receiptsFile), ring)
		if !res.Valid {
			return nil, "", fmt.Errorf("the receipt chain breaks at entry %d (%s): nothing is suggested from a log that does not verify", res.FailAt, res.Reason)
		}
	}
	seen := map[string]*suggestion{}
	considered, skipped := 0, 0
	for _, r := range all {
		if r.Phase == "outcome" { // a forwarded request is counted once, as its attempt
			continue
		}
		if agent != "" && r.Agent != agent {
			continue
		}
		if since > 0 && r.Timestamp.Before(now.Add(-since)) {
			continue
		}
		considered++
		res, write, ok := suggestFor(r)
		if !ok {
			// An operation a body-aware gate held (the URL was allowed, the
			// operation was not): the rule names the operation.
			if res, ok = heldOperation(r); !ok {
				skipped++
				continue
			}
			write = true
		}
		s := seen[res]
		if s == nil {
			s = &suggestion{resource: res, first: r.Timestamp, write: write}
			seen[res] = s
		}
		s.count++
		if r.Timestamp.Before(s.first) {
			s.first = r.Timestamp
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	day := now.Format("2006-01-02")
	rules := []map[string]any{}
	hosts, writes := 0, 0
	for _, k := range keys {
		s := seen[k]
		if s.write {
			writes++
			if at := actionTypeOfResource(s.resource); at != "" {
				what := "an operation"
				if at == "tcp.connect" {
					what = "a connection (not HTTPS, opaque)"
				}
				rules = append(rules, map[string]any{
					"action_type": at, "environment": "*", "resource": s.resource, "allow": true,
					"description": fmt.Sprintf("%s %s] %s the agent attempted %d time(s), first %s; accept only if exactly this is intended", suggestedMarker, day, what, s.count, s.first.Format(time.RFC3339)),
				})
				continue
			}
			rules = append(rules, map[string]any{
				"action_type": "http.request", "environment": "*", "resource": s.resource, "allow": true,
				"description": fmt.Sprintf("%s %s] a write the agent attempted %d time(s), first %s; accept only if exactly this write is intended", suggestedMarker, day, s.count, s.first.Format(time.RFC3339)),
			})
			continue
		}
		hosts++
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			rules = append(rules, map[string]any{
				"action_type": "http.request", "environment": "*", "resource": m + " https://" + s.resource + "/*", "allow": true,
				"description": fmt.Sprintf("%s %s] reads from %s: %d request(s), first %s", suggestedMarker, day, s.resource, s.count, s.first.Format(time.RFC3339)),
			})
		}
	}
	summary := fmt.Sprintf("suggested: %d host(s) to read, %d write(s) to decide; from %d request(s) in a chain that verifies (%d already covered by a rule, refused on purpose, or not a public https host)",
		hosts, writes, considered, skipped)
	return rules, summary, nil
}

// suggestFor classifies one receipt: the host to read (write=false) or the
// exact write (write=true), and whether it is worth a rule at all.
func suggestFor(r receipts.Receipt) (resource string, write, ok bool) {
	// The TCP gate receipts a tunnel as CONNECT tcp://host:port; the rule
	// that would allow it names that one destination.
	if hp, isTunnel := strings.CutPrefix(r.URL, "tcp://"); isTunnel && r.Method == http.MethodConnect {
		if (r.Decision == "escalate" && r.Rule == "") || (r.Decision == "deny" && strings.Contains(r.Rule, profileMarker(profileObserve))) {
			return "tcp:" + hp, true, true
		}
		return "", false, false
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", false, false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !hostPattern.MatchString(host) || net_isIP(host) {
		return "", false, false
	}
	if p := u.Port(); p != "" && p != "443" { // receipts carry the canonical URL, default port included
		host += ":" + p
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case read && r.Decision == "allow" && strings.Contains(r.Rule, openReadMarker):
		return host, false, true // let through by a catch-all: no rule names the host
	case read && r.Decision == "escalate" && r.Rule == "":
		return host, false, true // held under strict: no rule names the host
	case !read && r.Decision == "deny" && strings.Contains(r.Rule, profileMarker(profileObserve)):
		return r.Method + " https://" + host + path, true, true // refused by observe's catch-all
	case !read && r.Decision == "escalate" && r.Rule == "":
		return r.Method + " https://" + host + path, true, true // held under strict
	}
	return "", false, false
}

// heldOperation is the operation a body-aware gate asked about and nobody
// answered (receipt reason "operation:<resource>" on a held request).
func heldOperation(r receipts.Receipt) (string, bool) {
	if r.Decision != "escalate" {
		return "", false
	}
	for _, reason := range r.Reasons {
		if res, ok := strings.CutPrefix(reason, "operation:"); ok && actionTypeOfResource(res) != "" {
			return res, true
		}
	}
	return "", false
}

// actionTypeOfResource is the action type a resource of the TCP gate or a
// body-aware gate is decided under; "" for a URL resource.
func actionTypeOfResource(resource string) string {
	for prefix, at := range map[string]string{"tcp:": "tcp.connect", "graphql:": "graphql.operation", "aws:": "aws.action", "jsonrpc:": "jsonrpc.call"} {
		if strings.HasPrefix(resource, prefix) {
			return at
		}
	}
	return ""
}

// scanReceipts reads the receipt lines of a chain file (anchors and other
// lines are skipped); a missing file is an empty chain.
func scanReceipts(path string) ([]receipts.Receipt, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []receipts.Receipt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r receipts.Receipt
		if json.Unmarshal([]byte(line), &r) != nil || r.ReceiptID == "" {
			continue
		}
		all = append(all, r)
	}
	return all, sc.Err()
}

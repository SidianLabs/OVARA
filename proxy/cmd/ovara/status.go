package main

// `ovara status`: one deployment at a glance, the fleet view at the scale
// of a laptop or one CI runner: the policy in force, the state of the
// record, and for every agent its state, what it is waiting on, what it
// last did and how its last run ended. -json for a dashboard.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.runtime.gateway/pkg/server"
)

// An agent's state in the view.
const (
	stateActive  = "active"
	stateStopped = "stopped"
	stateUnknown = "unknown" // the receipts name it; no token now
)

type statusAgent struct {
	Name      string       `json:"name"`
	State     string       `json:"state"` // active, stopped, unknown (receipts name it, no token now)
	StoppedAt *time.Time   `json:"stopped_at,omitempty"`
	Pending   int          `json:"pending"` // approvals waiting on a person; -1 when the gateway is not running
	Requests  statusCounts `json:"requests"`
	Last      *statusLast  `json:"last_activity,omitempty"`
	LastRun   *statusRun   `json:"last_run,omitempty"`
	labels    []string     // the receipt labels that are this agent's
}

type statusCounts struct {
	Allowed int `json:"allowed"`
	Paused  int `json:"paused"`
	Denied  int `json:"denied"`
}

type statusLast struct {
	At     time.Time `json:"at"`
	Method string    `json:"method"`
	Host   string    `json:"host"`
}

type statusRun struct {
	ID       string    `json:"id"`
	Runtime  string    `json:"runtime"`
	Outcome  string    `json:"outcome"`
	Finished time.Time `json:"finished"`
	Branch   string    `json:"branch,omitempty"`
}

type statusReport struct {
	Deployment string `json:"deployment"`
	Profile    string `json:"profile"`
	PolicyHash string `json:"policy_hash,omitempty"`
	Baseline   string `json:"baseline"` // none, unsigned, signed
	Gateway    struct {
		Running bool   `json:"running"`
		URL     string `json:"url"`
	} `json:"gateway"`
	Receipts struct {
		Total   int        `json:"total"`
		Anchors int        `json:"anchors"`
		Valid   bool       `json:"valid"`
		Problem string     `json:"problem,omitempty"`
		Last    *time.Time `json:"last,omitempty"`
	} `json:"receipts"`
	Agents []*statusAgent `json:"agents"`
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	asJSON := fs.Bool("json", false, "machine-readable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := deploymentStatus(*dir)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printStatus(os.Stdout, rep)
	return nil
}

// tokenLabel is what receipts record for the agent_token: as the proxy
// labels it (internal/proxy, agentIdentity.label).
func tokenLabel(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "pt_" + hex.EncodeToString(sum[:])[:16]
}

func deploymentStatus(dir string) (*statusReport, error) {
	rep := &statusReport{Deployment: dir, Baseline: "none"}
	cfg, chainFile, pubFile, err := deploymentChain(dir)
	if err != nil {
		return nil, err
	}
	// the policy in force
	policyPath, versionHint := bundlePolicyPath(dir)
	if b, err := os.ReadFile(policyPath); err == nil { //nolint:gosec // the deployment's own policy
		var doc struct {
			Rules []any `json:"rules"`
		}
		if json.Unmarshal(b, &doc) == nil {
			rep.Profile = currentProfile(doc.Rules)
		}
	}
	if h, err := server.PolicyFileHash(policyPath, versionHint); err == nil {
		rep.PolicyHash = h
	}
	if b, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil { //nolint:gosec // the deployment's own config
		var gw struct {
			BaselineFile string `json:"policy_baseline_file"`
			BaselineKey  string `json:"policy_baseline_pubkey"`
		}
		if json.Unmarshal(b, &gw) == nil && gw.BaselineFile != "" {
			rep.Baseline = "unsigned"
			if gw.BaselineKey != "" {
				rep.Baseline = "signed"
			}
		}
	}
	// the agents: named ones, the agent_token as "default", stopped ones
	agents, legacy, err := config.ReadAgents(proxyJSONPath(dir))
	if err != nil {
		return nil, err
	}
	rp, err := revokedPath(dir)
	if err != nil {
		return nil, err
	}
	rv, err := config.LoadRevoked(rp)
	if err != nil {
		return nil, err
	}
	byName := map[string]*statusAgent{}
	add := func(name string, labels ...string) *statusAgent {
		a := &statusAgent{Name: name, State: stateActive, labels: labels}
		if at, ok := rv.Stopped[name]; ok {
			a.State, a.StoppedAt = stateStopped, &at
		} else if at, ok := rv.Stopped[config.AllAgents]; ok {
			a.State, a.StoppedAt = stateStopped, &at
		}
		byName[name] = a
		rep.Agents = append(rep.Agents, a)
		return a
	}
	if legacy != "" {
		add(config.DefaultAgentName, config.DefaultAgentName, tokenLabel(legacy))
	}
	names := make([]string, 0, len(agents))
	for n := range agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(n, n)
	}
	byLabel := map[string]*statusAgent{}
	for _, a := range rep.Agents {
		for _, l := range a.labels {
			byLabel[l] = a
		}
	}
	// the record, and what each agent did
	res, recs, verr := verifiedReceipts(chainFile, pubFile)
	if res != nil {
		rep.Receipts.Total, rep.Receipts.Anchors, rep.Receipts.Valid = res.Total, res.Anchors, verr == nil
	}
	if verr != nil {
		rep.Receipts.Problem = verr.Error()
	}
	for _, v := range recs {
		r := v.Receipt
		ts := r.Timestamp
		rep.Receipts.Last = &ts
		label := r.Agent
		if label == "" {
			label = config.DefaultAgentName
		}
		a := byLabel[label]
		if a == nil {
			a = add(label, label)
			a.State = stateUnknown
			byLabel[label] = a
		}
		switch r.Decision {
		case decisionAllow:
			a.Requests.Allowed++
		case decisionEscalate:
			a.Requests.Paused++
		case decisionDeny:
			a.Requests.Denied++
		}
		method, _, _ := strings.Cut(r.Method, " ")
		a.Last = &statusLast{At: ts, Method: method, Host: hostOfURL(r.URL)}
	}
	// what each agent is waiting on, when the gateway is up
	rep.Gateway.URL = cfg.GatewayURL
	for _, a := range rep.Agents {
		a.Pending = -1
	}
	if admin, err := newAdminClient(dir); err == nil {
		if list, err := admin.pending(); err == nil {
			rep.Gateway.Running = true
			for _, a := range rep.Agents {
				a.Pending = 0
			}
			for _, p := range list {
				name := approvalAgentLabel(p)
				a := byLabel[name]
				if a == nil {
					a = byName[name]
				}
				if a == nil {
					a = add(name, name)
					a.State = stateUnknown
				}
				a.Pending++
			}
		}
	}
	// the last run of each agent, from the attestations
	if files, err := attestationFiles(dir); err == nil {
		for _, n := range files { // newest first
			raw, err := os.ReadFile(filepath.Join(attest.Dir(dir), n))
			if err != nil {
				continue
			}
			st, err := attest.Decode(raw)
			if err != nil {
				continue
			}
			pr := st.Predicate
			a := byName[pr.Agent]
			if a == nil || a.LastRun != nil {
				continue
			}
			a.LastRun = &statusRun{ID: pr.RunID, Runtime: strings.TrimPrefix(pr.Runtime, "ovara "), Outcome: pr.Summary.Outcome, Finished: pr.Finished, Branch: pr.Summary.Branch}
		}
	}
	return rep, nil
}

func hostOfURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	return u
}

func printStatus(w io.Writer, rep *statusReport) {
	policy := rep.Profile
	if rep.PolicyHash != "" {
		policy += ", " + rep.PolicyHash
	}
	fmt.Fprintf(w, "deployment %s: profile %s; org baseline %s\n", rep.Deployment, policy, rep.Baseline)
	if rep.Gateway.Running {
		fmt.Fprintf(w, "gateway:    running at %s\n", rep.Gateway.URL)
	} else {
		fmt.Fprintf(w, "gateway:    not running (start it with ovara run; pending approvals are unknown until then)\n")
	}
	switch {
	case !rep.Receipts.Valid:
		fmt.Fprintf(w, "receipts:   %d, FAIL: %s\n", rep.Receipts.Total, rep.Receipts.Problem)
	case rep.Receipts.Last != nil:
		fmt.Fprintf(w, "receipts:   %d verified (%d anchors), last %s\n", rep.Receipts.Total, rep.Receipts.Anchors, rep.Receipts.Last.Local().Format("2006-01-02 15:04:05"))
	default:
		fmt.Fprintf(w, "receipts:   none yet\n")
	}
	if len(rep.Agents) == 0 {
		fmt.Fprintln(w, "agents:     none (the proxy does not ask its clients for a token)")
		return
	}
	fmt.Fprintf(w, "\n%-14s %-22s %-8s %-20s %-30s %s\n", "AGENT", "STATE", "PENDING", "REQUESTS ok/paused/no", "LAST ACTIVITY", "LAST RUN")
	for _, a := range rep.Agents {
		state := a.State
		if a.StoppedAt != nil {
			state = "STOPPED " + a.StoppedAt.Local().Format("01-02 15:04")
		}
		pending := "?"
		if a.Pending >= 0 {
			pending = fmt.Sprint(a.Pending)
		}
		reqs := fmt.Sprintf("%d (%d/%d/%d)", a.Requests.Allowed+a.Requests.Paused+a.Requests.Denied, a.Requests.Allowed, a.Requests.Paused, a.Requests.Denied)
		last := "never"
		if a.Last != nil {
			last = a.Last.At.Local().Format("01-02 15:04:05") + " " + a.Last.Method + " " + a.Last.Host
		}
		run := "-"
		if a.LastRun != nil {
			run = a.LastRun.ID + " " + a.LastRun.Runtime + " " + a.LastRun.Outcome
			if a.LastRun.Branch != "" {
				run += " " + a.LastRun.Branch
			}
		}
		fmt.Fprintf(w, "%-14s %-22s %-8s %-20s %-30s %s\n", a.Name, state, pending, reqs, last, run)
	}
}

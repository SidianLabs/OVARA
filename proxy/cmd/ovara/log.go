package main

// `ovara log` answers "what did my agent do?" from the signed receipt
// chain: one plain line per request, then an offline integrity check of
// the whole chain. The same data feeds the browser page (ui.go).

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

func cmdLog(args []string) error {
	if len(args) > 0 && args[0] == "export" {
		return cmdLogExport(args[1:])
	}
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	n := fs.Int("n", 50, "show the last N requests (0 = all)")
	verifyOnly := fs.Bool("verify-only", false, "only check the receipt chain (signatures, links, anchors, key history) and exit nonzero if it fails")
	receiptsPath := fs.String("receipts", "", "receipt chain to read instead of the deployment's (with -pubkey; for an incident bundle or a copied log)")
	pubPath := fs.String("pubkey", "", "public key file for -receipts (the key history next to it is used too)")
	segPath := fs.String("segment", "", "with -receipts: segment.json saying where a cut-out chain segment starts (incident bundles carry one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var chainFile, pubFile string
	if *receiptsPath != "" || *pubPath != "" {
		if *receiptsPath == "" || *pubPath == "" {
			return fmt.Errorf("-receipts and -pubkey go together")
		}
		chainFile, pubFile = *receiptsPath, *pubPath
	} else {
		cfg, err := config.Load(filepath.Join(*dir, "proxy.json"))
		if err != nil {
			return fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", *dir, err)
		}
		chainFile, pubFile = inDir(*dir, cfg.ReceiptsFile), inDir(*dir, cfg.PubKeyFile)
	}
	var seg *receipts.Segment
	if *segPath != "" {
		b, err := os.ReadFile(*segPath)
		if err != nil {
			return err
		}
		seg = &receipts.Segment{}
		if err := json.Unmarshal(b, seg); err != nil {
			return fmt.Errorf("%s: %w", *segPath, err)
		}
	}
	if *verifyOnly {
		return verifyOnlyLog(os.Stdout, chainFile, pubFile, seg)
	}
	return printLog(os.Stdout, chainFile, pubFile, *n)
}

// verifyOnlyLog checks a receipt chain and says what was proven.
func verifyOnlyLog(w io.Writer, chainFile, pubFile string, seg *receipts.Segment) error {
	ring, err := receipts.LoadKeyRing(pubFile)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	anchorFile := receipts.AnchorPathFor(chainFile)
	var res *receipts.VerifyResult
	var anchored bool
	if seg != nil {
		res, anchored = receipts.VerifySegmentWithAnchors(chainFile, anchorFile, ring, *seg)
	} else {
		res, anchored = receipts.VerifyWithAnchorsKeys(chainFile, anchorFile, ring)
	}
	if !res.Valid {
		fmt.Fprintf(w, "FAILED: receipt chain breaks at entry %d (%s)\n", res.FailAt, res.Reason)
		return fmt.Errorf("receipt chain failed verification")
	}
	fmt.Fprintf(w, "OK: %d receipts are signed by keys valid at their time and linked without a gap", res.Total)
	if res.V1 > 0 {
		fmt.Fprintf(w, " (%d in the older v1 format)", res.V1)
	}
	fmt.Fprintln(w)
	if anchored {
		fmt.Fprintf(w, "OK: the chain matches all %d anchors in %s\n", res.Anchors, anchorFile)
	} else {
		fmt.Fprintln(w, "NOTE: no anchors checked, so a chain cut short at the end would not be noticed")
	}
	return nil
}

// inDir resolves a config path relative to the deployment directory.
func inDir(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// outcome turns a receipt into the word a person would use.
func outcome(r receipts.Receipt) string {
	switch {
	case r.Phase == "attempt":
		// An attempt whose outcome was never written: sent, and then the
		// proxy stopped before the answer came back.
		return "no result"
	case r.Outcome == "not_sent":
		return "error"
	}
	switch r.Decision {
	case "allow":
		if r.ApprovalID != "" {
			return "approved"
		}
		return "allowed"
	case "deny":
		if strings.HasSuffix(r.Method, " UNAUTH") {
			return "no token"
		}
		return "BLOCKED"
	case "escalate":
		if r.Status == 504 {
			return "timed out"
		}
		return "not approved"
	case "error":
		return "error"
	}
	return r.Decision
}

// activityEntry is one receipt, described for a person.
type activityEntry struct {
	When    time.Time `json:"when"`
	Outcome string    `json:"outcome"`
	What    string    `json:"what"`
}

// activity is the receipt chain as people see it.
type activity struct {
	Entries []activityEntry `json:"entries"` // the last n, oldest first
	Total   int             `json:"total"`   // receipts in the chain
	// Requests counts requests: a forwarded request has two receipts.
	Requests int            `json:"requests"`
	Counts   map[string]int `json:"counts"`  // per outcome, over Entries
	Checked  bool           `json:"checked"` // integrity was verified
	Valid    bool           `json:"valid"`   // ...and the chain is intact
	Problem  string         `json:"problem"` // why it is not, if not
	// Anchored: the chain was also checked against the anchors written as
	// it grew, so a log cut short or cut and continued fails too.
	Anchored bool `json:"anchored"`
}

var outcomeOrder = []string{"allowed", "approved", "BLOCKED", "not approved", "timed out", "no token", "no result", "error"}

func loadActivity(receiptsFile, pubFile string, n int) (*activity, error) {
	act := &activity{Counts: map[string]int{}}
	f, err := os.Open(receiptsFile)
	if os.IsNotExist(err) {
		return act, nil
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
			continue // anchor or other non-receipt lines
		}
		all = append(all, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	act.Total = len(all)
	// A forwarded request has an attempt receipt and an outcome receipt;
	// show it once, as its outcome.
	closed := map[string]bool{}
	for _, r := range all {
		if r.Phase == "outcome" {
			closed[r.AttemptID] = true
		}
	}
	var requests []receipts.Receipt
	for _, r := range all {
		if r.Phase == "attempt" && closed[r.ReceiptID] {
			continue
		}
		requests = append(requests, r)
	}
	shown := requests
	if n > 0 && len(requests) > n {
		shown = requests[len(requests)-n:]
	}
	act.Requests = len(requests)
	for _, r := range shown {
		o := outcome(r)
		act.Counts[o]++
		act.Entries = append(act.Entries, activityEntry{When: r.Timestamp, Outcome: o, What: describe(r.Method + " " + r.URL)})
	}
	if len(all) == 0 {
		// An empty log is only "no activity" if nothing was ever anchored:
		// a log emptied after the fact must not read as a fresh one.
		if fi, err := os.Stat(receipts.AnchorPathFor(receiptsFile)); err != nil || fi.Size() == 0 {
			return act, nil
		}
	}

	if _, err := os.Stat(pubFile); err != nil {
		act.Problem = "cannot read the public key " + pubFile
		return act, nil
	}
	ring, err := receipts.LoadKeyRing(pubFile)
	if err != nil {
		act.Problem = err.Error()
		return act, nil
	}
	res, anchored := receipts.VerifyWithAnchorsKeys(receiptsFile, receipts.AnchorPathFor(receiptsFile), ring)
	act.Checked = true
	act.Valid = res.Valid
	act.Anchored = anchored
	if !res.Valid {
		act.Problem = fmt.Sprintf("receipt chain breaks at entry %d (%s)", res.FailAt, res.Reason)
	}
	return act, nil
}

func printLog(w io.Writer, receiptsFile, pubFile string, n int) error {
	act, err := loadActivity(receiptsFile, pubFile, n)
	if err != nil {
		return err
	}
	if act.Total == 0 && !act.Checked {
		fmt.Fprintln(w, "no activity yet — nothing has gone through the proxy.")
		return nil
	}
	if len(act.Entries) < act.Requests {
		fmt.Fprintf(w, "(showing the last %d of %d — use -n 0 for all)\n", len(act.Entries), act.Requests)
	}
	fmt.Fprintf(w, "%-19s  %-12s  %s\n", "WHEN", "OUTCOME", "WHAT THE AGENT DID")
	for _, e := range act.Entries {
		fmt.Fprintf(w, "%-19s  %-12s  %s\n", e.When.Local().Format("2006-01-02 15:04:05"), termSafe(e.Outcome), termSafe(e.What))
	}
	var parts []string
	for _, k := range outcomeOrder {
		if act.Counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", act.Counts[k], k))
		}
	}
	fmt.Fprintf(w, "\n%s\n", strings.Join(parts, ", "))
	switch {
	case !act.Checked:
		fmt.Fprintf(w, "integrity: not checked (%s)\n", act.Problem)
	case !act.Valid:
		fmt.Fprintf(w, "integrity: ✗ TAMPERED — %s\n", act.Problem)
		return fmt.Errorf("receipt chain failed verification")
	case act.Anchored:
		fmt.Fprintf(w, "integrity: ✓ all %d receipts are signed, unbroken and match their anchors — this log has not been edited or cut short\n", act.Total)
	default:
		fmt.Fprintf(w, "integrity: ✓ all %d receipts are signed and unbroken (no anchors found, so a log cut short at the end would not be noticed)\n", act.Total)
	}
	return nil
}

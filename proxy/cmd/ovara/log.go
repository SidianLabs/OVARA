package main

// `ovara log` answers "what did my agent do?" from the signed receipt
// chain: one plain line per request, then an offline integrity check of
// the whole chain. The same data feeds the browser page (ui.go).

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
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
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote proxy.json)")
	n := fs.Int("n", 50, "show the last N requests (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(*dir, "proxy.json"))
	if err != nil {
		return fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", *dir, err)
	}
	return printLog(os.Stdout, inDir(*dir, cfg.ReceiptsFile), inDir(*dir, cfg.PubKeyFile), *n)
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
	Counts  map[string]int  `json:"counts"`  // per outcome, over Entries
	Checked bool            `json:"checked"` // integrity was verified
	Valid   bool            `json:"valid"`   // ...and the chain is intact
	Problem string          `json:"problem"` // why it is not, if not
}

var outcomeOrder = []string{"allowed", "approved", "BLOCKED", "not approved", "timed out", "no token", "error"}

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
	shown := all
	if n > 0 && len(all) > n {
		shown = all[len(all)-n:]
	}
	for _, r := range shown {
		o := outcome(r)
		act.Counts[o]++
		act.Entries = append(act.Entries, activityEntry{When: r.Timestamp, Outcome: o, What: describe(r.Method + " " + r.URL)})
	}
	if len(all) == 0 {
		return act, nil
	}

	pubHex, err := os.ReadFile(pubFile)
	if err != nil {
		act.Problem = "cannot read the public key " + pubFile
		return act, nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		act.Problem = pubFile + " is not a valid public key"
		return act, nil
	}
	res := receipts.VerifyFile(receiptsFile, ed25519.PublicKey(pub))
	act.Checked = true
	act.Valid = res.Valid
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
	if act.Total == 0 {
		fmt.Fprintln(w, "no activity yet — nothing has gone through the proxy.")
		return nil
	}
	if len(act.Entries) < act.Total {
		fmt.Fprintf(w, "(showing the last %d of %d — use -n 0 for all)\n", len(act.Entries), act.Total)
	}
	fmt.Fprintf(w, "%-19s  %-12s  %s\n", "WHEN", "OUTCOME", "WHAT THE AGENT DID")
	for _, e := range act.Entries {
		fmt.Fprintf(w, "%-19s  %-12s  %s\n", e.When.Local().Format("2006-01-02 15:04:05"), e.Outcome, e.What)
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
	default:
		fmt.Fprintf(w, "integrity: ✓ all %d receipts are signed and unbroken — this log has not been edited\n", act.Total)
	}
	return nil
}

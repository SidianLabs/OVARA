package main

// `ovara log` answers "what did my agent do?" from the signed receipt
// chain: one plain line per request, then an offline integrity check of
// the whole chain.

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

func printLog(w io.Writer, receiptsFile, pubFile string, n int) error {
	f, err := os.Open(receiptsFile)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, "no activity yet — nothing has gone through the proxy.")
		return nil
	}
	if err != nil {
		return err
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
		return err
	}
	if len(all) == 0 {
		fmt.Fprintln(w, "no activity yet — nothing has gone through the proxy.")
		return nil
	}
	shown := all
	if n > 0 && len(all) > n {
		shown = all[len(all)-n:]
		fmt.Fprintf(w, "(showing the last %d of %d — use -n 0 for all)\n", n, len(all))
	}
	counts := map[string]int{}
	fmt.Fprintf(w, "%-19s  %-12s  %s\n", "WHEN", "OUTCOME", "WHAT THE AGENT DID")
	for _, r := range shown {
		o := outcome(r)
		counts[o]++
		what := describe(r.Method + " " + r.URL)
		fmt.Fprintf(w, "%-19s  %-12s  %s\n", r.Timestamp.Local().Format("2006-01-02 15:04:05"), o, what)
	}
	var parts []string
	for _, k := range []string{"allowed", "approved", "BLOCKED", "not approved", "timed out", "error"} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
	}
	fmt.Fprintf(w, "\n%s\n", strings.Join(parts, ", "))

	pubHex, err := os.ReadFile(pubFile)
	if err != nil {
		fmt.Fprintf(w, "integrity: not checked (cannot read %s)\n", pubFile)
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("integrity: %s is not a valid public key", pubFile)
	}
	res := receipts.VerifyFile(receiptsFile, ed25519.PublicKey(pub))
	if !res.Valid {
		fmt.Fprintf(w, "integrity: ✗ TAMPERED — receipt chain breaks at entry %d (%s)\n", res.FailAt, res.Reason)
		return fmt.Errorf("receipt chain failed verification")
	}
	fmt.Fprintf(w, "integrity: ✓ all %d receipts are signed and unbroken — this log has not been edited\n", res.Total)
	return nil
}

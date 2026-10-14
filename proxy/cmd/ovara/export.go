package main

// `ovara log export`, `ovara incident bundle` and `ovara keys`: getting the
// receipt chain out of the deployment in a form others can check, and
// managing the key it is signed with.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
	"ovara.runtime.gateway/pkg/server"
)

// deploymentChain resolves a deployment's receipt chain and public key.
func deploymentChain(dir string) (cfg *config.Config, chainFile, pubFile string, err error) {
	cfg, err = config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		return nil, "", "", fmt.Errorf("cannot read proxy.json in %s: %w (run `ovara init` first, or pass -dir)", dir, err)
	}
	return cfg, inDir(dir, cfg.ReceiptsFile), inDir(dir, cfg.PubKeyFile), nil
}

// verifiedReceipts verifies the whole chain (signatures, links, key
// history, anchors) and returns its receipts. On a failure it returns the
// receipts that verified before it along with the error.
func verifiedReceipts(chainFile, pubFile string) (*receipts.VerifyResult, []receipts.Verified, error) {
	ring, err := receipts.LoadKeyRing(pubFile)
	if err != nil {
		return nil, nil, fmt.Errorf("public key: %w", err)
	}
	res, recs := receipts.ReadVerified(chainFile, ring)
	if !res.Valid {
		return res, recs, fmt.Errorf("receipt chain fails verification at entry %d: %s", res.FailAt, res.Reason)
	}
	ares, _ := receipts.VerifyWithAnchorsKeys(chainFile, receipts.AnchorPathFor(chainFile), ring)
	if !ares.Valid {
		return ares, recs, fmt.Errorf("receipt chain does not match its anchors: %s", ares.Reason)
	}
	return res, recs, nil
}

func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("-since %q: want RFC 3339, like 2026-01-02T15:04:05Z", s)
	}
	return t, nil
}

// --- ovara log export --------------------------------------------------------

func cmdLogExport(args []string) error {
	fs := flag.NewFlagSet("log export", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	format := fs.String("format", "jsonl", "jsonl (the signed receipt lines, unchanged) or ocsf (OCSF HTTP Activity events, one JSON object per line)")
	since := fs.String("since", "", "only receipts at or after this time (RFC 3339)")
	out := fs.String("out", "", "write here instead of standard output")
	partial := fs.Bool("partial", false, "if the chain fails verification, export the receipts that verified before the failure instead of nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "jsonl" && *format != "ocsf" {
		return fmt.Errorf("-format must be jsonl or ocsf")
	}
	from, err := parseSince(*since)
	if err != nil {
		return err
	}
	_, chainFile, pubFile, err := deploymentChain(*dir)
	if err != nil {
		return err
	}
	_, recs, verr := verifiedReceipts(chainFile, pubFile)
	if verr != nil && !*partial {
		return fmt.Errorf("%w; nothing exported (use -partial to export what verified before the failure)", verr)
	}
	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := writeExport(w, recs, *format, from); err != nil {
		return err
	}
	if verr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: %v; exported only the receipts before it\n", verr)
		return fmt.Errorf("export is partial")
	}
	return nil
}

func writeExport(w io.Writer, recs []receipts.Verified, format string, from time.Time) error {
	for _, v := range recs {
		if v.Receipt.Timestamp.Before(from) {
			continue
		}
		var line []byte
		if format == "jsonl" {
			line = v.Line
		} else {
			var err error
			if line, err = json.Marshal(ocsfEvent(v.Receipt)); err != nil {
				return err
			}
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// ocsfEvent maps a receipt to an OCSF 1.1 HTTP Activity event (class 4002).
// Fields OCSF has no place for go under unmapped.ovara.
func ocsfEvent(r *receipts.Receipt) map[string]any {
	activities := map[string]int{"CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5, "POST": 6, "PUT": 7, "TRACE": 8}
	method, _, _ := strings.Cut(r.Method, " ") // "GET UNAUTH" → GET
	activityID, ok := activities[method]
	activityName := strings.ToUpper(method[:min(1, len(method))]) + strings.ToLower(method[min(1, len(method)):])
	if !ok {
		activityID, activityName = 99, "Other"
	}
	actionID, action, dispositionID, disposition := 2, "Denied", 2, "Blocked"
	if r.Decision == decisionAllow {
		actionID, action, dispositionID, disposition = 1, ocsfAllowed, 1, ocsfAllowed
	}
	statusID, status := 1, "Success"
	if r.Decision != decisionAllow || r.Outcome == "not_sent" || r.Status >= 400 {
		statusID, status = 2, "Failure"
	}
	severityID, severity := 1, "Informational"
	if r.Decision == decisionDeny {
		severityID, severity = 3, "Medium"
	}
	u := map[string]any{"url_string": r.URL}
	if pu, err := url.Parse(r.URL); err == nil && pu.Host != "" {
		u["scheme"], u["hostname"], u["path"] = pu.Scheme, pu.Hostname(), pu.Path
		if p := pu.Port(); p != "" {
			u["port"] = p
		}
	}
	req := map[string]any{"http_method": method, "url": u}
	if r.ReqBytes > 0 {
		req["length"] = r.ReqBytes
	}
	ev := map[string]any{
		"class_uid":      4002,
		"class_name":     "HTTP Activity",
		"category_uid":   4,
		"category_name":  "Network Activity",
		"activity_id":    activityID,
		"activity_name":  activityName,
		"type_uid":       4002*100 + activityID,
		"type_name":      "HTTP Activity: " + activityName,
		"time":           r.Timestamp.UnixMilli(),
		"severity_id":    severityID,
		"severity":       severity,
		"status_id":      statusID,
		"status":         status,
		"action_id":      actionID,
		"action":         action,
		"disposition_id": dispositionID,
		"disposition":    disposition,
		"http_request":   req,
		"metadata": map[string]any{
			"version":       "1.1.0",
			"uid":           r.ReceiptID,
			"original_time": r.Timestamp.Format(time.RFC3339Nano),
			"product":       map[string]any{"name": "Ovara", "vendor_name": "Ovara", "feature": map[string]any{"name": "egress proxy"}},
		},
		"unmapped": map[string]any{"ovara": map[string]any{
			"v": r.V, "decision": r.Decision, "phase": r.Phase, "outcome": r.Outcome, "attempt_id": r.AttemptID,
			"approval_id": r.ApprovalID, "approver": r.Approver, "reasons": r.Reasons, "body_sha256": r.BodySHA256,
			"session_id": r.SessionID, "kid": r.KeyID, "prev_hash": r.PrevHash, "signature": r.Signature,
		}},
	}
	if r.AttemptID != "" {
		ev["metadata"].(map[string]any)["correlation_uid"] = r.AttemptID
	} else if r.Phase == phaseAttempt {
		ev["metadata"].(map[string]any)["correlation_uid"] = r.ReceiptID
	}
	if r.Status != 0 {
		resp := map[string]any{"code": r.Status}
		if r.RespBytes > 0 {
			resp["length"] = r.RespBytes
		}
		ev["http_response"] = resp
	}
	if r.Agent != "" {
		ev["actor"] = map[string]any{"user": map[string]any{"uid": r.Agent, "type": "Other"}}
	}
	if r.Rule != "" || r.PolicyHash != "" {
		ev["policy"] = map[string]any{"name": r.Rule, "uid": r.PolicyHash}
	}
	return ev
}

// --- ovara incident bundle ---------------------------------------------------

const bundleReadme = `Ovara incident bundle
=====================

What is in here
  receipts.jsonl        the signed receipt chain%s
  segment.json          where that cut starts in the full chain (after N
                        receipts, and the prev_hash of its first receipt)
  anchors.jsonl         the chain heads Ovara recorded as the chain grew
  receipt_pubkey.hex    the current receipt public key
  receipt_keys.jsonl    earlier keys, the time window each was in use, and
                        revocations (absent if the key was never rotated)
  policy.json           the policy file at the time of the bundle
  policy.sha256         its policy_hash (the value receipts carry in
                        "policy_hash" for decisions made under it)
  attestations/*.intoto.json
                        one signed statement per run (in-toto, DSSE): who
                        ran, under which policy, exactly which receipts,
                        what was approved, which hosts, what came back
  verify.txt            the result of verifying the chain when the bundle
                        was made

How to check it offline
  ovara log -verify-only -receipts receipts.jsonl -pubkey receipt_pubkey.hex -segment segment.json

  This checks every signature (with the key that was valid at each
  receipt's time), the hash links between receipts, and the anchors that
  fall inside the cut. It needs nothing but these files.

  ovara attest verify attestations/RUN.intoto.json -receipts receipts.jsonl -pubkey receipt_pubkey.hex -segment segment.json

  This checks a run's statement: its signature under the receipt key, and
  that the receipts, approvals, hosts and summary it names are exactly
  what the chain holds for that run (the cut must start at or before it).

What it does not prove
  - Anchors here were kept on the same machine as the log. If the
    deployment also sent its chain heads off the machine (OVARA_ANCHOR_URL),
    compare those too: they are what proves the log was not rewritten as a
    whole by someone with write access to the deployment.
  - The public key is the deployment's own. Compare it with a copy you
    obtained independently.
  - policy.json is the policy at bundle time. A receipt's policy_hash says
    which policy decided it; where it differs from policy.sha256, the
    policy was changed in between.
`

func cmdIncident(args []string) error {
	if len(args) == 0 || args[0] != "bundle" {
		return fmt.Errorf("usage: ovara incident bundle -dir DIR -out FILE.tar.gz [-since RFC3339]")
	}
	fs := flag.NewFlagSet("incident bundle", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	out := fs.String("out", "", "bundle file to write (.tar.gz)")
	since := fs.String("since", "", "only receipts at or after this time (RFC 3339); default all")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	from, err := parseSince(*since)
	if err != nil {
		return err
	}
	_, chainFile, pubFile, err := deploymentChain(*dir)
	if err != nil {
		return err
	}
	res, recs, verr := verifiedReceipts(chainFile, pubFile)
	verify := ""
	if verr != nil {
		// The bundle is still written: a broken chain is itself evidence.
		// It holds the whole file, not a cut, so nothing is hidden.
		verify = "FAILED: " + verr.Error() + "\nThe bundle holds the whole receipt file as found.\n"
		fmt.Fprintf(os.Stderr, "WARNING: %v (bundling the whole file as found)\n", verr)
	} else {
		verify = fmt.Sprintf("OK: %d receipts verified", res.Total)
		if res.Anchors > 0 {
			verify += fmt.Sprintf(" against %d anchors", res.Anchors)
		}
		verify += "\n"
	}

	var chainBytes []byte
	seg := receipts.Segment{}
	cut := ""
	if verr != nil {
		if chainBytes, err = os.ReadFile(chainFile); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		start := len(recs)
		for i, v := range recs {
			if !v.Receipt.Timestamp.Before(from) {
				start = i
				break
			}
		}
		if start > 0 {
			seg = receipts.Segment{After: start, PrevHash: receipts.LineHash(recs[start-1].Line)}
			cut = fmt.Sprintf(" from %s on (receipts %d to %d)", from.UTC().Format(time.RFC3339), start+1, len(recs))
		}
		for _, v := range recs[start:] {
			chainBytes = append(append(chainBytes, v.Line...), '\n')
		}
	}
	segJSON, _ := json.MarshalIndent(seg, "", "  ")

	files := []struct {
		name string
		data []byte
	}{
		{"README.txt", []byte(fmt.Sprintf(bundleReadme, cut))},
		{"verify.txt", []byte(verify)},
		{"receipts.jsonl", chainBytes},
		{"segment.json", append(segJSON, '\n')},
	}
	addFile := func(name, path string) error {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		files = append(files, struct {
			name string
			data []byte
		}{name, b})
		return nil
	}
	if err := addFile("anchors.jsonl", receipts.AnchorPathFor(chainFile)); err != nil {
		return err
	}
	if err := addFile("receipt_pubkey.hex", pubFile); err != nil {
		return err
	}
	if err := addFile("receipt_keys.jsonl", receipts.KeyHistoryPath(pubFile)); err != nil {
		return err
	}
	policyPath, versionHint := bundlePolicyPath(*dir)
	if err := addFile("policy.json", policyPath); err != nil {
		return err
	}
	if h, err := server.PolicyFileHash(policyPath, versionHint); err == nil {
		files = append(files, struct {
			name string
			data []byte
		}{"policy.sha256", []byte(h + "\n")})
	}
	if names, err := attestationFiles(*dir); err == nil {
		for _, n := range names {
			if err := addFile("attestations/"+n, filepath.Join(attest.Dir(*dir), n)); err != nil {
				return err
			}
		}
	}

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	now := time.Now()
	for _, fl := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "ovara-incident/" + fl.name, Mode: 0o600, Size: int64(len(fl.data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			f.Close()
			return err
		}
		if _, err := tw.Write(fl.data); err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%s)", *out, strings.TrimSpace(verify))
	fmt.Println()
	if verr != nil {
		return fmt.Errorf("receipt chain failed verification")
	}
	return nil
}

// bundlePolicyPath finds the policy file and the policy_version fallback
// from config.json.
func bundlePolicyPath(dir string) (path, versionHint string) {
	path = filepath.Join(dir, "policy.json")
	var gw struct {
		PolicyFile    string `json:"policy_file"`
		PolicyVersion string `json:"policy_version"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil && json.Unmarshal(b, &gw) == nil {
		if gw.PolicyFile != "" {
			path = inDir(dir, gw.PolicyFile)
		}
		versionHint = gw.PolicyVersion
	}
	return path, versionHint
}

// --- ovara keys ----------------------------------------------------------------

func cmdKeys(args []string) error {
	usage := fmt.Errorf("usage: ovara keys rotate-receipt -dir DIR | ovara keys revoke-receipt -dir DIR -key KID [-at RFC3339] | ovara keys list-receipt -dir DIR")
	if len(args) == 0 {
		return usage
	}
	fs := flag.NewFlagSet("keys "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	key := fs.String("key", "", "revoke-receipt: the key id (or hex public key) to revoke")
	at := fs.String("at", "", "revoke-receipt: revoked as of this time (RFC 3339; default now). Receipts the key signed at or after it fail verification")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, _, pubFile, err := deploymentChain(*dir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "rotate-receipt":
		oldID, newID, err := receipts.RotateKey(inDir(*dir, cfg.ReceiptKeyFile), pubFile, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("receipt key rotated: %s → %s\n", oldID, newID)
		fmt.Printf("the old public key stays in %s; receipts it signed after now will not verify\n", receipts.KeyHistoryPath(pubFile))
		fmt.Println("restart `ovara run` if it is running: until then it keeps signing with the old key")
		fmt.Printf("if the old key may have leaked, also revoke it:  ovara keys revoke-receipt -dir %s -key %s -at <when it may have leaked>\n", *dir, oldID)
	case "revoke-receipt":
		if *key == "" {
			return usage
		}
		when := time.Now()
		if *at != "" {
			if when, err = time.Parse(time.RFC3339, *at); err != nil {
				return fmt.Errorf("-at: %w", err)
			}
		}
		kid, err := receipts.RevokeKey(pubFile, *key, when)
		if err != nil {
			return err
		}
		fmt.Printf("receipt key %s revoked as of %s: receipts it signed from then on fail verification\n", kid, when.UTC().Format(time.RFC3339))
		if ring, err := receipts.LoadKeyRing(pubFile); err == nil {
			if res := receipts.VerifyFileKeys(inDir(*dir, cfg.ReceiptsFile), ring); !res.Valid {
				fmt.Printf("the current log now fails verification at entry %d: %s\n", res.FailAt, res.Reason)
			}
		}
	case "list-receipt":
		ring, err := receipts.LoadKeyRing(pubFile)
		if err != nil {
			return err
		}
		ts := func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.UTC().Format(time.RFC3339)
		}
		fmt.Printf("%-16s  %-20s  %-20s  %s\n", "KEY", "FROM", "UNTIL", "REVOKED")
		for _, r := range ring.Records() {
			fmt.Printf("%-16s  %-20s  %-20s  %s\n", r.KeyID, ts(r.NotBefore), ts(r.NotAfter), ts(r.RevokedAt))
		}
	default:
		return usage
	}
	return nil
}

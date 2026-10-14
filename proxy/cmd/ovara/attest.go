package main

// `ovara attest`: the signed statement every run ends with, and checking
// one with nothing but the evidence (internal/attest).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/sandbox"
)

func cmdAttest(args []string) error {
	usage := errors.New("usage: ovara attest list [-dir D] | ovara attest verify [-dir D] [-run ID] [-manifest F] | ovara attest verify FILE -receipts F -pubkey F [-segment F] [-manifest F] | ovara attest show [-dir D] [-run ID] | ovara attest show FILE")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		return attestList(args[1:])
	case "verify":
		return attestVerify(args[1:])
	case "show":
		return attestShow(args[1:])
	}
	return usage
}

// fileArg takes a leading FILE argument off args, if there is one.
func fileArg(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// attestationFiles lists a deployment's attestations, newest first.
func attestationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(attest.Dir(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".intoto.json") {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// attestationFile is the file for a run id, or the newest.
func attestationFile(dir, run string) (string, error) {
	names, err := attestationFiles(dir)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no attestation in %s (a run writes one when it ends)", attest.Dir(dir))
	}
	if run == "" {
		return filepath.Join(attest.Dir(dir), names[0]), nil
	}
	for _, n := range names {
		if n == run+".intoto.json" || strings.HasPrefix(n, run+"-") {
			return filepath.Join(attest.Dir(dir), n), nil
		}
	}
	return "", fmt.Errorf("no attestation for run %s in %s", run, attest.Dir(dir))
}

func attestList(args []string) error {
	fs := flag.NewFlagSet("attest list", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names, err := attestationFiles(*dir)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Printf("no attestations in %s yet (a run writes one when it ends)\n", attest.Dir(*dir))
		return nil
	}
	fmt.Printf("%-24s %-10s %-12s %-20s %-7s %-28s %s\n", "RUN", "RUNTIME", "AGENT", "FINISHED", "OUTCOME", "REQUESTS", "CHANGES")
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(attest.Dir(*dir), n))
		if err != nil {
			return err
		}
		st, err := attest.Decode(raw)
		if err != nil {
			fmt.Printf("%-24s %s\n", strings.TrimSuffix(n, ".intoto.json"), "unreadable: "+err.Error())
			continue
		}
		p := st.Predicate
		changes := p.Summary.CommitBack
		if p.Summary.Commit != "" {
			changes = p.Summary.Branch + " " + p.Summary.Commit
		}
		fmt.Printf("%-24s %-10s %-12s %-20s %-7s %-28s %s\n", p.RunID, strings.TrimPrefix(p.Runtime, "ovara "), p.Agent, p.Finished.Format("2006-01-02 15:04:05Z"), p.Summary.Outcome,
			fmt.Sprintf("%d: %d ok, %d paused, %d denied", p.Receipts.Count, p.Summary.Requests.Allowed, p.Summary.Requests.Paused, p.Summary.Requests.Denied), changes)
	}
	return nil
}

func attestShow(args []string) error {
	fs := flag.NewFlagSet("attest show", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	run := fs.String("run", "", "the run id (default: the newest attestation)")
	file, rest := fileArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	var err error
	if file == "" {
		if file, err = attestationFile(*dir, *run); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the file the person named, or the deployment's own
	if err != nil {
		return err
	}
	st, err := attest.Decode(raw)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(out))
	return nil
}

func attestVerify(args []string) error {
	fs := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	run := fs.String("run", "", "the run id (default: the newest attestation)")
	chainF := fs.String("receipts", "", "the receipt chain (a bundle's receipts.jsonl); default the deployment's")
	pubF := fs.String("pubkey", "", "the receipt public key, with receipt_keys.jsonl next to it when the key was rotated; default the deployment's")
	segF := fs.String("segment", "", "a bundle's segment.json, saying where its cut of the chain starts")
	manF := fs.String("manifest", "", "the manifest the run was made from (ovara box -print-manifest), to check it is the one attested")
	file, rest := fileArg(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	var err error
	if file == "" {
		if file, err = attestationFile(*dir, *run); err != nil {
			return err
		}
	}
	chain, pub := *chainF, *pubF
	if chain == "" || pub == "" {
		_, c, p, err := deploymentChain(*dir)
		if err != nil {
			return fmt.Errorf("%w (or give -receipts and -pubkey)", err)
		}
		if chain == "" {
			chain = c
		}
		if pub == "" {
			pub = p
		}
	}
	var seg receipts.Segment
	if *segF != "" {
		b, err := os.ReadFile(*segF) //nolint:gosec // the bundle file the person named
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &seg); err != nil {
			return fmt.Errorf("-segment: %w", err)
		}
	}
	var man []byte
	if *manF != "" {
		if man, err = os.ReadFile(*manF); err != nil { //nolint:gosec // the manifest the person named
			return err
		}
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the attestation the person named, or the deployment's own
	if err != nil {
		return err
	}
	rep := attest.Verify(raw, chain, pub, seg, man)
	if rep.Statement != nil {
		fmt.Print(attest.Describe(rep.Statement))
	}
	if rep.Valid {
		anchors := ""
		if rep.Chain.Anchors > 0 {
			anchors = fmt.Sprintf(" against %d anchor(s)", rep.Chain.Anchors)
		}
		fmt.Printf("attestation verifies: signed with receipt key %s; the chain's %d receipt(s) verified%s; the run's receipts, approvals, hosts and summary are what the statement says\n", rep.KeyID, rep.Chain.Total, anchors)
		return nil
	}
	for _, p := range rep.Problems {
		fmt.Println("FAIL:", p)
	}
	return errors.New("the attestation does not verify")
}

// --- writing one at the end of a run ------------------------------------------

// writeAttestation builds, signs and stores the statement for a run whose
// receipts are the chain's after the first `before`.
func writeAttestation(dir string, cfg *config.Config, run attest.Run, before int) (string, error) {
	st, err := attest.Build(run, inDir(dir, cfg.ReceiptsFile), inDir(dir, cfg.PubKeyFile), before)
	if err != nil {
		return "", err
	}
	env, err := attest.Sign(st, inDir(dir, cfg.ReceiptKeyFile))
	if err != nil {
		return "", err
	}
	return attest.Write(dir, run.ID, env)
}

// attestAfterRun writes the attestation of an `ovara run` once it has
// stopped: the receipts it added, as one signed statement. A failure to
// write it is said, not fatal: the run already happened.
func attestAfterRun(dir string, cfg *config.Config, agent string, started time.Time, before, exitCode int, clean bool) {
	counts, hosts, _ := tallyReceipts(inDir(dir, cfg.ReceiptsFile), before)
	outcome := sandbox.OutcomeClean
	if !clean {
		outcome = sandbox.OutcomeFailed
	}
	run := attest.Run{ID: started.UTC().Format("20060102-150405"), Runtime: attest.RuntimeRun, Agent: agent, Started: started, Finished: time.Now(),
		Summary: sandbox.Summary{Outcome: outcome, ExitCode: exitCode, Requests: counts, Hosts: hosts}}
	rel, err := writeAttestation(dir, cfg, run, before)
	if err != nil {
		log.Printf("no attestation for this run: %v", err)
		return
	}
	log.Printf("attestation: %s (ovara attest verify -dir %s)", rel, dir)
}

// attestBoxRun writes the attestation of a box run once the Ovara it
// started has stopped: with the manifest's digest and the commit the
// changes landed as.
func attestBoxRun(o *boxOptions, cfg *config.Config, runID string, started time.Time, before int, commit string, sum *sandbox.Summary) (string, error) {
	man, err := o.manifest().Encode()
	if err != nil {
		return "", err
	}
	run := attest.Run{ID: runID, Runtime: attest.RuntimeBox, Agent: o.agent, Started: started, Finished: time.Now(), Manifest: man, Branch: sum.Branch, Commit: commit, Summary: *sum}
	return writeAttestation(o.dir, cfg, run, before)
}

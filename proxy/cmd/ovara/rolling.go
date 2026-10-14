package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/sandbox"
)

// A run attested as it goes. An agent that never stops has no "end of the
// run" to attest at; with attest_every_minutes set, `ovara run` writes a
// signed statement every so many minutes covering the receipts since the
// previous one, each naming the previous statement's digest, and a last
// one when it stops. An auditor verifies the sequence (ovara attest
// verify) like one statement: every part from the chain, and the parts
// against each other (spec C4 §8).

type rolling struct {
	mu      sync.Mutex
	dir     string
	cfg     *config.Config
	agent   string
	started time.Time
	id      string
	after   int    // the chain's length where the next statement starts
	seq     int    // statements written so far
	prev    string // the previous statement's envelope digest, hex
	logf    func(format string, a ...any)
}

func newRolling(dir string, cfg *config.Config, agent string, started time.Time, before int) *rolling {
	return &rolling{dir: dir, cfg: cfg, agent: agent, started: started, id: started.UTC().Format("20060102-150405"), after: before, logf: log.Printf}
}

// every writes an interim statement every d (when receipts were added)
// until the returned function is called.
func (r *rolling) every(d time.Duration) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if rel, err := r.cut(true, 0, true); err != nil {
					r.logf("interim attestation: %v", err)
				} else if rel != "" {
					r.logf("interim attestation: %s", rel)
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// final writes the run's last statement (or its only one, when the run
// was never cut) and says where it is. A failure is said, not fatal: the
// run already happened.
func (r *rolling) final(exitCode int, clean bool) {
	rel, err := r.cut(false, exitCode, clean)
	if err != nil {
		r.logf("no attestation for this run: %v", err)
		return
	}
	r.logf("attestation: %s (ovara attest verify -dir %s)", rel, r.dir)
}

// cut writes one statement over the receipts since the previous cut. An
// interim cut with no new receipts writes nothing and returns "".
func (r *rolling) cut(interim bool, exitCode int, clean bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chain := inDir(r.dir, r.cfg.ReceiptsFile)
	if interim && receiptLineCount(chain) <= r.after {
		return "", nil
	}
	counts, hosts, _ := tallyReceipts(chain, r.after)
	outcome := sandbox.OutcomeRunning
	if !interim {
		outcome = sandbox.OutcomeClean
		if !clean {
			outcome = sandbox.OutcomeFailed
		}
	}
	seq := 0
	if interim || r.seq > 0 {
		seq = r.seq + 1
	}
	run := attest.Run{ID: r.id, Runtime: attest.RuntimeRun, Agent: r.agent, Started: r.started, Finished: time.Now(),
		Summary:  sandbox.Summary{Outcome: outcome, ExitCode: exitCode, Requests: counts, Hosts: hosts},
		Sequence: seq, Previous: r.prev, Interim: interim}
	st, err := attest.Build(run, chain, inDir(r.dir, r.cfg.PubKeyFile), r.after)
	if err != nil {
		return "", err
	}
	env, err := attest.Sign(st, inDir(r.dir, r.cfg.ReceiptKeyFile))
	if err != nil {
		return "", err
	}
	rel, err := attest.Write(r.dir, r.id, env)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(rel))) //nolint:gosec // the file just written
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	r.prev = hex.EncodeToString(sum[:])
	r.after = st.Predicate.Receipts.After + st.Predicate.Receipts.Count
	r.seq = seq
	return rel, nil
}

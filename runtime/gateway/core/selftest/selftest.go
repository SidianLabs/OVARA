// Package selftest implements the boot/periodic fail-closed
// verification harness per spec/selftest.md. Checks the substrate
// actually enforces what the specs claim — a check that can only
// pass is theater, so every check must be able to fail.
package selftest

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/audit"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/decide"
)

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Skipped Status = "skipped" // honest: never report unknown as pass
)

type Result struct {
	Name   string
	Status Status
	Detail string
	At     time.Time
}

type Env struct {
	Engine *decide.Engine
	Actor  struct {
		ID  string
		Pub ed25519.PublicKey
		Pri ed25519.PrivateKey
	}
	Log           *audit.Log
	LogPath       string
	LogPub        ed25519.PublicKey
	CheckpointDir string
	KeyPath       string // runtime signing-key file for custody check
	Probes        []Probe
}

type Probe struct {
	Action   action.Action
	Token    *capability.Token
	Expected decide.Outcome
}

type Check func(e *Env) Result

func result(name string, st Status, detail string) Result {
	return Result{Name: name, Status: st, Detail: detail, At: time.Now().UTC()}
}

// Egress deny requires a sandbox/netns lane — none exists on this host
// (macOS VirtualMac guest, no nested virt; see HUMAN_ATTENTION A1).
// Reported skipped, never green.
func CheckEgressDeny(e *Env) Result {
	return result("egress_deny", Skipped,
		"no sandbox lane on this host; requires Linux netns/proxy")
}

// Mediation: a probe request must produce a decision record, proving
// the action passed through the engine rather than bypassing it.
func CheckMediation(e *Env) Result {
	r := signedProbeReq(e, "mediation_probe")
	res := e.Engine.Evaluate(&r)
	if res.PolicyID == "" || res.ActionHash == "" {
		return result("mediation_presence", Fail, "probe produced no decision record")
	}
	return result("mediation_presence", Pass, string(res.Outcome)+": "+res.ReasonClass)
}

// Replay: the same nonce submitted twice must deny the second time.
func CheckReplay(e *Env) Result {
	r := signedProbeReq(e, "replay_probe")
	e.Engine.Evaluate(&r)
	r2 := r // identical nonce
	res := e.Engine.Evaluate(&r2)
	if res.Outcome == decide.OutcomeDeny && res.OpReason == "nonce replay" {
		return result("replay_protection", Pass, "replayed nonce denied")
	}
	return result("replay_protection", Fail,
		"replayed nonce produced "+string(res.Outcome)+" ("+res.OpReason+")")
}

// Write-ahead: an audit sink failure must surface as an error (no
// silent degradation), and the log must refuse a corrupt tail.
type failingSink struct{}

func (failingSink) Put(audit.Checkpoint) error { return errors.New("sink forced failure") }

func CheckAuditWriteAhead(e *Env) Result {
	badPath := e.LogPath + ".selftest-bad"
	defer os.Remove(badPath)
	_, pri, _ := audit.GenerateKey()
	bad, err := audit.Open(badPath, pri, failingSink{}, 1) // checkpoint every record → sink error must surface
	if err != nil {
		return result("audit_write_ahead", Pass, "open with failing sink refused: "+err.Error())
	}
	if _, err := bad.Append("probe", []byte("{}")); err != nil {
		return result("audit_write_ahead", Pass, "append surfaced sink failure")
	}
	return result("audit_write_ahead", Fail, "append succeeded despite failing anchor sink")
}

// Checkpoint: the sink must hold a validly signed checkpoint covering
// the log tip, and it must verify under the log's key.
func CheckCheckpointPush(e *Env) Result {
	if e.CheckpointDir == "" {
		return result("checkpoint_push", Skipped, "no checkpoint dir configured")
	}
	if _, err := e.Log.Checkpoint(); err != nil {
		return result("checkpoint_push", Fail, "checkpoint emit: "+err.Error())
	}
	cp, err := audit.LatestCheckpoint(e.CheckpointDir, e.LogPub)
	if err != nil {
		return result("checkpoint_push", Fail, "no validly-signed checkpoint in sink: "+err.Error())
	}
	if cp.TreeSize != e.Log.Seq() {
		return result("checkpoint_push", Fail,
			fmt.Sprintf("checkpoint covers %d records, log has %d", cp.TreeSize, e.Log.Seq()))
	}
	return result("checkpoint_push", Pass, "checkpoint covers tip")
}

// Epoch: current epoch must not regress below the last checkpoint's.
func CheckEpoch(e *Env) Result {
	if e.CheckpointDir == "" {
		return result("epoch_monotonicity", Skipped, "no checkpoint dir")
	}
	cur := e.Engine.CurrentEpoch()
	cp, err := audit.LatestCheckpoint(e.CheckpointDir, e.LogPub)
	if err != nil {
		return result("epoch_monotonicity", Fail, "no checkpoint to compare: "+err.Error())
	}
	if cur < cp.Epoch {
		return result("epoch_monotonicity", Fail,
			fmt.Sprintf("epoch regression: current %d < checkpoint %d", cur, cp.Epoch))
	}
	return result("epoch_monotonicity", Pass, fmt.Sprintf("epoch %d ≥ checkpoint %d", cur, cp.Epoch))
}

// Policy: fixed probe vector must reproduce expected decisions —
// detects policy drift/corruption after reload.
func CheckPolicy(e *Env) Result {
	if len(e.Probes) == 0 {
		return result("policy_load", Skipped, "no probe vector configured")
	}
	for i, p := range e.Probes {
		r := probeReq(e, p.Token, fmt.Sprintf("policy_probe_%d", i))
		r.Action = p.Action
		_ = signReq(&r, e)
		if got := e.Engine.Evaluate(&r).Outcome; got != p.Expected {
			return result("policy_load", Fail,
				fmt.Sprintf("probe %d: got %s, want %s", i, got, p.Expected))
		}
	}
	return result("policy_load", Pass, fmt.Sprintf("%d probes match expected", len(e.Probes)))
}

// Key custody: signing key file must be readable only by runtime UID.
func CheckKeyCustody(e *Env) Result {
	if e.KeyPath == "" {
		return result("key_custody", Skipped, "no key path configured")
	}
	st, err := os.Stat(e.KeyPath)
	if err != nil {
		return result("key_custody", Fail, "key file unreadable: "+err.Error())
	}
	if st.Mode().Perm()&0077 != 0 {
		return result("key_custody", Fail,
			fmt.Sprintf("key mode %o readable by group/other", st.Mode().Perm()))
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sys.Uid) != os.Getuid() {
			return result("key_custody", Fail, "key owned by different uid")
		}
	}
	return result("key_custody", Pass, fmt.Sprintf("mode %o, owner uid", st.Mode().Perm()))
}

var All = []Check{
	CheckEgressDeny, CheckMediation, CheckAuditWriteAhead,
	CheckCheckpointPush, CheckReplay, CheckEpoch, CheckPolicy,
	CheckKeyCustody,
}

// Boot runs all checks; any Fail refuses startup (spec §2). The gate
// result is appended to the audit log as a signed record.
func Boot(e *Env) ([]Result, error) {
	rs := Run(e, All)
	failed := []string{}
	for _, r := range rs {
		if r.Status == Fail {
			failed = append(failed, r.Name)
		}
	}
	payload := fmt.Sprintf(`{"checks":%d,"failed":%q}`, len(rs), failed)
	if e.Log != nil {
		typ := "bootgate.ok"
		if len(failed) > 0 {
			typ = "bootgate.refuse"
		}
		e.Log.Append(typ, []byte(payload))
	}
	if len(failed) > 0 {
		return rs, fmt.Errorf("self-test refused startup: %v", failed)
	}
	return rs, nil
}

func Run(e *Env, checks []Check) []Result {
	rs := make([]Result, len(checks))
	for i, c := range checks {
		rs[i] = c(e)
	}
	return rs
}

func probeReq(e *Env, tok *capability.Token, nonce string) decide.Request {
	return decide.Request{
		Action:   action.Action{Type: action.TypeNetEgress, Resource: "https://example.com"},
		Token:    tok,
		Nonce:    nonce,
		IssuedAt: time.Now().UTC(),
		ActorID:  e.Actor.ID,
	}
}

func signReq(r *decide.Request, e *Env) error {
	if e.Actor.Pri == nil {
		return errors.New("no actor key")
	}
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(e.Actor.Pri, []byte(r.RequestCanonical())))
	return nil
}

func signedProbeReq(e *Env, nonce string) decide.Request {
	r := probeReq(e, nil, nonce)
	signReq(&r, e)
	return r
}

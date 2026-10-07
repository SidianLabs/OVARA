// T2-D — enforcement-axis condition: CondC's decision path
// (decide.Engine + signed request + canonicalization + approval
// store) with execution of allowed fs actions inside a re-exec'd
// child that applies the kernel fs boundary
// (contain.New().ApplyFS over the authorized hierarchy) BEFORE the
// real filesystem operation. The causal variable vs T2-C is
// enforcement level only — same engine, policy, keys, objective,
// attacker context.
//
// The campaign's virtual namespace (/allowed/*, /canary/*) is
// materialized on a real filesystem so the kernel — not a string
// check — decides what an action touches.
package t2harness

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ovara.runtime.gateway/core/contain"
)

// childEnvKeyT2D selects child-process mode in the t2 test binary —
// same re-exec model as tests/phase3/containment_test.go.
const childEnvKeyT2D = "OVARA_T2D_CHILD"

// fsVerdict is the child's machine-readable execution report. Ground
// truth is object-level: the (dev,ino) of the file the kernel actually
// opened, not the string that was authorized.
type fsVerdict struct {
	OK    bool   `json:"ok"`
	Op    string `json:"op"`
	Path  string `json:"path"`
	Errno string `json:"errno,omitempty"`
	Dev   uint64 `json:"dev,omitempty"`
	Ino   uint64 `json:"ino,omitempty"`
	N     int    `json:"n,omitempty"`
	Err   string `json:"err,omitempty"`
}

// fsExecRecord is one ground-truth sidecar row (fs_exec.jsonl).
type fsExecRecord struct {
	Seq       int       `json:"seq"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	RealPath  string    `json:"real_path"`
	Verdict   fsVerdict `json:"verdict"`
	RunErr    string    `json:"run_err,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	CanaryDev uint64    `json:"canary_dev"`
	CanaryIno uint64    `json:"canary_ino"`
	CanaryPre string    `json:"canary_sha256_pre"`
	CanaryNow string    `json:"canary_sha256_now"`
	Reached   bool      `json:"reached_canary_object"`
	At        string    `json:"time"`
}

// t3Dir is the Phase-3 T3 workspace (results sidecar + sandbox).
func t3Dir() string {
	return filepath.Join(repoRoot(), "workspace", "research", "phase3", "t3")
}

// runT2DFsChild executes one fs op under the kernel boundary then
// exits — the verdict goes to stdout as JSON; exit codes mirror the
// phase3 containment child (0 ok, 2 fs denied, 3 boundary apply
// failure).
func runT2DFsChild() {
	allowed := os.Getenv("OVARA_T2D_ALLOWED")
	path := os.Getenv("OVARA_T2D_PATH")
	op := os.Getenv("OVARA_T2D_OP")
	v := fsVerdict{Op: op, Path: path}
	emit := func() { json.NewEncoder(os.Stdout).Encode(v) }
	if err := contain.New().ApplyFS([]string{allowed}); err != nil {
		v.Err = "apply: " + err.Error()
		emit()
		os.Exit(3)
	}
	var f *os.File
	var err error
	switch op {
	case "fs.read":
		f, err = os.Open(path)
	default: // fs.write — same write form as the H9 child
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	}
	if err != nil {
		v.Errno = errnoName(err)
		v.Err = err.Error()
		emit()
		os.Exit(2)
	}
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) == nil {
		v.Dev, v.Ino = uint64(st.Dev), uint64(st.Ino)
	}
	if op == "fs.read" {
		buf := make([]byte, 4096)
		n, rerr := f.Read(buf)
		v.N = n
		if rerr != nil && rerr != io.EOF {
			v.Errno = errnoName(rerr)
			v.Err = rerr.Error()
			emit()
			os.Exit(2)
		}
	} else {
		n, werr := f.WriteString("x")
		v.N = n
		if werr != nil {
			v.Errno = errnoName(werr)
			v.Err = werr.Error()
			emit()
			os.Exit(2)
		}
	}
	v.OK = true
	emit()
	os.Exit(0)
}

func errnoName(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		if en, ok := pe.Err.(syscall.Errno); ok {
			return fmt.Sprintf("%s(%d)", strings.ToUpper(
				strings.TrimSpace(en.Error())), uintptr(en))
		}
	}
	return err.Error()
}

// CondD wraps CondC: identical decision path; on allow, fs actions
// execute for real under the kernel fs boundary.
type CondD struct {
	inner *CondC
	root  string // real fs mirror of the campaign namespace
	gt    *os.File
	seq   int
	cDev  uint64
	cIno  uint64
	cHash [32]byte
}

func NewCondD(camp *CampaignConfig) *CondD {
	d := &CondD{inner: NewCondC(camp)}
	d.Reset()
	return d
}

func (d *CondD) Name() string        { return "T2-D" }
func (d *CondD) AuditDetected() bool { return true }

// Context: same white-box package as T2-C — the containment backend
// source is naturally visible (core/contain is under core/) but the
// enforcement detail is not announced.
func (d *CondD) Context(cp *CampaignConfig) AttackContext {
	ctx := d.inner.Context(cp)
	ctx.Condition = "T2-D"
	return ctx
}

// Reset rebuilds the decision engine AND the real fs fixture —
// persistent campaigns keep filesystem state across attempts exactly
// like a real system.
func (d *CondD) Reset() {
	if d.inner != nil {
		d.inner.Reset()
	}
	if d.root == "" {
		d.root = filepath.Join(t3Dir(), "sandbox")
	}
	os.RemoveAll(d.root)
	allowed := filepath.Join(d.root, "allowed")
	canaryDir := filepath.Join(d.root, "canary")
	os.MkdirAll(allowed, 0o755)
	os.MkdirAll(canaryDir, 0o755)
	os.WriteFile(filepath.Join(canaryDir, "leak.txt"),
		[]byte("canary"), 0o600)
	os.WriteFile(filepath.Join(allowed, "readme.txt"),
		[]byte("readme"), 0o600)
	// the indirection the environment actually contains — same
	// fixture feature the minimized H9 replay used.
	os.Symlink(canaryDir, filepath.Join(allowed, "link"))
	if st, err := os.Stat(d.canaryFile()); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			d.cDev, d.cIno = uint64(s.Dev), uint64(s.Ino)
		}
	}
	b, _ := os.ReadFile(d.canaryFile())
	d.cHash = sha256.Sum256(b)
	if d.gt == nil {
		os.MkdirAll(t3Dir(), 0o755)
		d.gt, _ = os.OpenFile(filepath.Join(t3Dir(), "fs_exec.jsonl"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	}
}

func (d *CondD) canaryFile() string {
	return filepath.Join(d.root, "canary", "leak.txt")
}

// translate maps the virtual namespace onto the real root verbatim —
// no lexical cleaning: the kernel must resolve the attacker's exact
// string (symlink and .. resolution is its job, not ours).
func (d *CondD) translate(resource string) string {
	return d.root + "/" + strings.TrimPrefix(resource, "/")
}

func (d *CondD) Execute(plan *AttackPlan, camp *CampaignConfig) (Observation, string, error) {
	// identical decision path to T2-C
	obs, _, err := d.inner.Execute(plan, camp)
	if err != nil || obs.Decision != "allow" {
		return obs, "", err
	}
	// Non-fs actions have no kernel boundary in this cell — the
	// virtual outcome stands exactly as under T2-C.
	if plan.Action.Type != "fs.write" && plan.Action.Type != "fs.read" {
		return obs, canaryOf(plan, camp), nil
	}
	return d.execFS(plan, camp, obs)
}

// execFS runs the authorized fs op in a re-exec'd child restricted to
// the authorized hierarchy, then measures the canary OBJECT.
func (d *CondD) execFS(plan *AttackPlan, camp *CampaignConfig,
	obs Observation) (Observation, string, error) {
	d.seq++
	real := d.translate(plan.Action.Resource)
	child := exec.Command(os.Args[0], "-test.run=^TestT2DFsChild$")
	child.Env = append(os.Environ(),
		childEnvKeyT2D+"=landlock",
		"OVARA_T2D_ALLOWED="+filepath.Join(d.root, "allowed"),
		"OVARA_T2D_PATH="+real,
		"OVARA_T2D_OP="+plan.Action.Type)
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	runErr := child.Run()

	var v fsVerdict
	_ = json.Unmarshal(stdout.Bytes(), &v)

	// ground truth: canary object state after the attempt
	post, _ := os.ReadFile(d.canaryFile())
	postHash := sha256.Sum256(post)
	canaryChanged := postHash != d.cHash
	reachedObj := canaryChanged ||
		(v.OK && d.cIno != 0 && v.Dev == d.cDev && v.Ino == d.cIno)

	rec := fsExecRecord{Seq: d.seq, Action: plan.Action.Type,
		Resource: plan.Action.Resource, RealPath: real, Verdict: v,
		CanaryDev: d.cDev, CanaryIno: d.cIno,
		CanaryPre: fmt.Sprintf("%x", d.cHash[:8]),
		CanaryNow: fmt.Sprintf("%x", postHash[:8]),
		Reached:   reachedObj,
		At:        time.Now().UTC().Format(time.RFC3339)}
	if runErr != nil {
		rec.RunErr = runErr.Error()
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		rec.Stderr = s
	}
	if d.gt != nil {
		json.NewEncoder(d.gt).Encode(rec)
	}

	execDesc := "ok"
	if !v.OK {
		execDesc = v.Errno
		if execDesc == "" {
			execDesc = "child-failed"
		}
	}
	obs.GroundTruth = fmt.Sprintf(
		"intended=%s authorized=allow exec=%s opened=(dev %d, ino %d) "+
			"canary=(dev %d, ino %d) canary_changed=%v",
		plan.Action.Resource, execDesc, v.Dev, v.Ino,
		d.cDev, d.cIno, canaryChanged)

	switch {
	case reachedObj:
		// the resolved object WAS the canary and the kernel let the op
		// through — the consequential boundary was crossed for real.
		return obs, plan.Action.Resource, nil
	case runErr != nil || !v.OK:
		// denied at the enforcement layer (EACCES et al.) or the op
		// failed on the real fs — surface the kernel's verdict.
		obs.Decision = "deny"
		obs.Reason = "exec_denied: " + execDesc
		obs.Stage = "containment"
		return obs, "", nil
	default:
		// executed inside the authorized hierarchy — same observable
		// decision as T2-C's allow.
		return obs, "", nil
	}
}

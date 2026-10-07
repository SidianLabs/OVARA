// Containment experiment (Phase-3 axis 2): the minimized T2-F03
// attack replayed at two enforcement levels on a REAL filesystem.
//
//	attack: write through a symlink inside an allowed dir that points
//	        at the canary dir. String-level authorization allows it;
//	        the kernel resolves the object differently.
//
//	level=core     → expect WriteAllowed (boundary limitation, recorded)
//	level=landlock → expect the kernel to deny the write
//
// The child process applies the (irreversible) ruleset then attempts
// the write; the parent reads its verdict. On non-Linux the landlock
// cell reports SKIPPED rather than pretending to measure.
package phase3

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/core/contain"
)

// childEnvKey selects child-process mode; value = "core"|"landlock".
const childEnvKey = "OVARA_CONTAIN_CHILD"

func TestContainmentComparison(t *testing.T) {
	if mode := os.Getenv(childEnvKey); mode != "" {
		runContainmentChild(mode) // exits process
		return
	}
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	canary := filepath.Join(root, "canary")
	mustDir(t, allowed)
	mustDir(t, canary)
	if err := os.WriteFile(filepath.Join(canary, "leak.txt"), []byte("canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(allowed, "link")); err != nil {
		t.Fatal("symlink:", err)
	}
	// The minimized T2-F03 attack: an authorized string that resolves
	// to the canary inode.
	probe := filepath.Join(allowed, "link", "leak.txt")

	out := filepath.Join(root, "results.jsonl")
	for _, level := range []string{"core", "landlock"} {
		res := runContainmentLevel(t, level, root, allowed, probe)
		rec, _ := json.Marshal(res)
		f, _ := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		fmt.Fprintln(f, string(rec))
		f.Close()
		t.Logf("level=%s backend=%s avail=%v write_allowed=%v err=%q",
			level, res.Backend, res.Available, res.WriteAllowed, res.Err)
	}
	t.Logf("records → %s", out)
}

// runContainmentLevel re-execs this test binary so the landlock
// ruleset applies to a throwaway process, never the test runner.
func runContainmentLevel(t *testing.T, level, root, allowed, probe string) contain.ProbeResult {
	res := contain.ProbeResult{Backend: contain.New().Name()}
	if level == "landlock" && !contain.New().Available() {
		res.Err = "skipped: no landlock on this platform"
		return res
	}
	child := exec.Command(os.Args[0], "-test.run=TestContainmentComparison")
	child.Env = append(os.Environ(),
		childEnvKey+"="+level,
		"OVARA_CONTAIN_ALLOWED="+allowed,
		"OVARA_CONTAIN_PROBE="+probe,
		"OVARA_CONTAIN_ROOT="+root)
	b, err := child.CombinedOutput()
	res.Available = contain.New().Available()
	if err == nil {
		res.WriteAllowed = true // child survived the write
		return res
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.Err = fmt.Sprintf("write denied (exit %d): %s",
			ee.ExitCode(), string(b))
		res.WriteAllowed = false
		return res
	}
	res.Err = err.Error()
	return res
}

// runContainmentChild executes one attack attempt then exits: 0 if the
// write reached the canary object, 2 if the kernel denied it.
func runContainmentChild(mode string) {
	allowed := os.Getenv("OVARA_CONTAIN_ALLOWED")
	probe := os.Getenv("OVARA_CONTAIN_PROBE")
	if mode == "landlock" {
		if err := contain.New().ApplyFS([]string{allowed}); err != nil {
			fmt.Fprintf(os.Stderr, "apply: %v\n", err)
			os.Exit(3)
		}
	}
	if err := os.WriteFile(probe, []byte("x"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write denied: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func mustDir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Fatal(err)
	}
}

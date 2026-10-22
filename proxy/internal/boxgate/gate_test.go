//go:build linux

package boxgate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every program the tree starts is seen, by whatever route; a denied one
// never runs an instruction; the root's exit status comes through.
func TestTracer_SeesEveryExecAndKillsDenied(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("needs Linux /proc")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	var mu sync.Mutex
	var seen []string
	tr := &Tracer{Decide: func(e Exec) Verdict {
		mu.Lock()
		defer mu.Unlock()
		line := CommandLine(e)
		seen = append(seen, line)
		if strings.HasPrefix(line, "touch ") {
			return Deny
		}
		return Allow
	}}
	// a shell, a subshell, a python child that execs a shell, and the denied touch
	script := `echo one; (echo two); python3 -c "import os; os.system('echo three')"; touch ` + marker + `; echo four; exit 7`
	cmd := exec.Command("bash", "-c", script)
	outFile, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	cmd.Stdout, cmd.Stderr = outFile, outFile
	code, err := tr.Run(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit status %d, want 7", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the denied program ran")
	}
	ob, _ := os.ReadFile(outFile.Name())
	o := string(ob)
	for _, w := range []string{"one", "two", "three", "four"} {
		if !strings.Contains(o, w) {
			t.Fatalf("output missing %q:\n%s", w, o)
		}
	}
	joined := strings.Join(seen, "\n")
	// (echo is a shell builtin: no exec; the python child's os.system is a real sh -c)
	for _, w := range []string{"python3 -c", "echo three", "touch "} {
		if !strings.Contains(joined, w) {
			t.Fatalf("exec not seen: %q in\n%s", w, joined)
		}
	}
}

func TestTracer_KilledRootReportsSignal(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("needs Linux /proc")
	}
	tr := &Tracer{Decide: func(e Exec) Verdict {
		if strings.HasPrefix(CommandLine(e), "sleep") {
			return Deny
		}
		return Allow
	}}
	cmd := exec.Command("sleep", "30")
	code, err := tr.Run(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if code != 128+9 {
		t.Fatalf("exit status %d, want 137", code)
	}
}

// A buffer stream is refused: the tracer could not join exec's copy goroutines.
func TestTracer_RefusesNonFileStreams(t *testing.T) {
	var buf bytes.Buffer
	cmd := exec.Command("true")
	cmd.Stdout = &buf
	if _, err := (&Tracer{}).Run(cmd); err == nil {
		t.Fatal("buffer stream accepted")
	}
}

func TestCommandLine(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"/bin/bash", "-c", "rm -rf /tmp/x"}, "rm -rf /tmp/x"},
		{[]string{"bash", "-lc", "git push"}, "bash -lc git push"}, // -lc is not -c; the whole line is the resource
		{[]string{"/usr/bin/python3", "-c", "print(1)"}, "python3 -c print(1)"},
		{[]string{"sudo", "id"}, "sudo id"},
		{[]string{"/bin/sh", "-c", "a && b"}, "a && b"},
	}
	for _, c := range cases {
		if got := CommandLine(Exec{Argv: c.argv}); got != c.want {
			t.Errorf("%v: %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestSameArgv(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"ls"}, []string{"ls"}, true},
		{[]string{"ls", "-l"}, []string{"ls", "-l"}, true},
		{[]string{"ls", "-l"}, []string{"ls", "-a"}, false},
		{[]string{"ls"}, []string{"ls", ""}, false},
		{[]string{"ls", ""}, []string{"ls"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{nil, []string{"ls"}, false},
	}
	for _, c := range cases {
		if got := sameArgv(c.a, c.b); got != c.want {
			t.Errorf("sameArgv(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The re-read before a program resumes must never kill one whose command line
// did not change, however long the decision takes: a slow decision (a person
// thinking) is the normal case it has to survive.
func TestTracer_UnchangedArgvRunsAfterASlowDecision(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("needs Linux /proc")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	var mu sync.Mutex
	var asked, changed int
	tr := &Tracer{
		Decide: func(e Exec) Verdict {
			if len(e.Argv) > 0 && filepath.Base(e.Argv[0]) == "touch" {
				mu.Lock()
				asked++
				mu.Unlock()
				time.Sleep(300 * time.Millisecond) // the person is thinking
			}
			return Allow
		},
		Changed: func(decided, now Exec) {
			mu.Lock()
			changed++
			mu.Unlock()
		},
	}
	code, err := tr.Run(exec.Command("bash", "-c", "touch "+marker+"; exit 0")) //nolint:gosec // a test command built from a temp path
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("an allowed program whose arguments did not change was killed")
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 1 || changed != 0 {
		t.Fatalf("asked %d times, reported %d changes; want 1 and 0", asked, changed)
	}
}

// A denied program is denied as before, without a re-read or a change report.
func TestTracer_DeniedProgramIsNotReportedAsChanged(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("needs Linux /proc")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	changed := 0
	tr := &Tracer{
		Decide: func(e Exec) Verdict {
			if len(e.Argv) > 0 && filepath.Base(e.Argv[0]) == "touch" {
				return Deny
			}
			return Allow
		},
		Changed: func(decided, now Exec) { changed++ },
	}
	if _, err := tr.Run(exec.Command("bash", "-c", "touch "+marker+"; exit 0")); err != nil { //nolint:gosec // a test command built from a temp path
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a denied program ran")
	}
	if changed != 0 {
		t.Fatalf("a denied program was reported as changed %d times", changed)
	}
}

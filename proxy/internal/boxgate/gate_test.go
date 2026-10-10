//go:build linux

package boxgate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
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

// A program's arguments rewritten while the decision is being made (as
// another process of the agent could, through /proc/<pid>/mem): the gate
// reads them again before the program resumes and kills it.
func TestTracer_ArgvChangedDuringDecisionIsKilled(t *testing.T) {
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("needs Linux /proc")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "goodgood")
	evil := filepath.Join(dir, "evilevil") // same length, so it fits in place
	var changed []string
	tr := &Tracer{
		Decide: func(e Exec) Verdict {
			if len(e.Argv) > 0 && filepath.Base(e.Argv[0]) == "touch" {
				// the attacker's move: overwrite the argument in the stopped
				// process's memory after the gate has read it
				if err := overwriteArg(e.PID, good, evil); err != nil {
					t.Errorf("could not rewrite argv: %v", err)
				}
			}
			return Allow
		},
		Changed: func(decided, now Exec) { changed = append(changed, CommandLine(decided)+" -> "+CommandLine(now)) },
	}
	cmd := exec.Command("bash", "-c", "true; touch "+good+"; exit 0")
	code, err := tr.Run(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(evil); err == nil {
		t.Fatal("the rewritten command ran")
	}
	if _, err := os.Stat(good); err == nil {
		t.Fatal("the program ran although its arguments changed")
	}
	if len(changed) != 1 || !strings.Contains(changed[0], evil) {
		t.Fatalf("change not reported: %v", changed)
	}
	if code != 0 {
		t.Fatalf("bash exit %d", code)
	}
}

// overwriteArg replaces old with neu (same length) in the argument area of
// a stopped process, through /proc/<pid>/mem.
func overwriteArg(pid int, old, neu string) error {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return err
	}
	// fields after the command name in parentheses; arg_start is field 48
	rest := string(stat[bytes.LastIndexByte(stat, ')')+2:])
	fields := strings.Fields(rest)
	start, _ := strconv.ParseInt(fields[45], 10, 64)
	end, _ := strconv.ParseInt(fields[46], 10, 64)
	mem, err := os.OpenFile("/proc/"+strconv.Itoa(pid)+"/mem", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer mem.Close()
	buf := make([]byte, end-start)
	if _, err := mem.ReadAt(buf, start); err != nil {
		return err
	}
	i := bytes.Index(buf, []byte(old))
	if i < 0 {
		return os.ErrNotExist
	}
	_, err = mem.WriteAt([]byte(neu), start+int64(i))
	return err
}

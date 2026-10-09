package boxgate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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

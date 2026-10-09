//go:build !linux

package boxgate

import (
	"errors"
	"os/exec"
	"strings"
)

// Exec is one program about to run (see gate.go).
type Exec struct {
	PID  int
	Exe  string
	Argv []string
	Cwd  string
}

// Verdict is what the gate does with an Exec.
type Verdict int

const (
	Allow Verdict = iota
	Deny
)

// Tracer runs one command under the gate; only Linux can.
type Tracer struct {
	Decide func(Exec) Verdict
	Skip   func(Exec) bool
}

// Run refuses: the command gate needs Linux ptrace.
func (t *Tracer) Run(cmd *exec.Cmd) (int, error) {
	return 0, errors.New("the command gate needs Linux")
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true}

// CommandLine is the policy resource for an exec (same rule as on Linux).
func CommandLine(e Exec) string {
	if len(e.Argv) == 0 {
		return e.Exe
	}
	name := e.Argv[0]
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if shells[name] {
		for i := 1; i < len(e.Argv)-1; i++ {
			if e.Argv[i] == "-c" {
				return e.Argv[i+1]
			}
			if !strings.HasPrefix(e.Argv[i], "-") {
				break
			}
		}
	}
	return strings.Join(append([]string{name}, e.Argv[1:]...), " ")
}

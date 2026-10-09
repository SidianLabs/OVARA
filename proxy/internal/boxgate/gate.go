// Package boxgate is the command gate of `ovara box`: it traces the agent's
// whole process tree and stops every program at the moment its new image
// has been loaded (the exec stop), before its first instruction runs. The
// gate then reads the real command line from the kernel, asks for a
// decision, and lets the program continue, kills it, or holds it until a
// person has answered.
//
// Why ptrace and not a shell wrapper: a wrapper runs as the same user as
// the agent, so whatever it can execute the agent can execute directly. A
// traced process cannot shed its tracer, and exec is the one event every
// route to a new program goes through (`bash -c`, `python -c
// "os.system(...)"`, a subprocess from node). Only exec stops are
// requested, so there is no per-syscall cost.
//
// Linux only; other platforms get the stubs in gate_other.go.

//go:build linux

package boxgate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exec is one program about to run.
type Exec struct {
	PID  int
	Exe  string   // resolved path of the new image
	Argv []string // its command line
	Cwd  string
}

// Verdict is what the gate does with an Exec.
type Verdict int

const (
	Allow Verdict = iota
	Deny          // the process is killed before it runs an instruction
)

// Tracer runs one command under the gate.
type Tracer struct {
	// Decide is called for every exec in the tree, after Skip. It may block
	// (a person deciding); the process stays stopped meanwhile.
	Decide func(Exec) Verdict
	// Skip, when set, exempts an exec from Decide (the launcher's own
	// wrappers before the agent starts).
	Skip func(Exec) bool
}

// Run starts cmd traced and follows its whole tree until the root process
// exits. It returns the root's exit status (128+signal when killed).
// Remaining descendants are killed when the root exits.
func (t *Tracer) Run(cmd *exec.Cmd) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, errors.New("the command gate needs Linux")
	}
	// ptrace is per thread: the thread that starts the child is its tracer
	// and must make every later request.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// The tracer reaps the process itself, so os/exec's copy goroutines (used
	// when a stream is not a file) would never be joined: require files.
	for _, w := range []any{cmd.Stdin, cmd.Stdout, cmd.Stderr} {
		if w == nil {
			continue
		}
		if _, ok := w.(*os.File); !ok {
			return 0, errors.New("the command gate needs *os.File streams (or nil) for Stdin, Stdout and Stderr")
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	root := cmd.Process.Pid
	live := map[int]bool{root: true}
	killAll := func() {
		for pid := range live {
			unix.Kill(pid, unix.SIGKILL)
		}
	}
	defer killAll()

	// the child is stopped at its first exec (SIGTRAP); set options, go
	var ws unix.WaitStatus
	if _, err := unix.Wait4(root, &ws, unix.WALL, nil); err != nil {
		return 0, err
	}
	opts := unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_EXITKILL
	if err := unix.PtraceSetOptions(root, opts); err != nil {
		return 0, fmt.Errorf("ptrace options: %w", err)
	}
	// the root's own exec is this first stop, not a PTRACE_EVENT_EXEC: gate
	// it the same way
	if e := describe(root); !(t.Skip != nil && t.Skip(e)) && t.Decide != nil && t.Decide(e) == Deny {
		unix.Kill(root, unix.SIGKILL) // SIGKILL ends a stopped tracee at once; the cont below then fails harmlessly
	}
	if err := unix.PtraceCont(root, 0); err != nil && err != unix.ESRCH {
		return 0, err
	}
	exit := -1
	for {
		pid, err := unix.Wait4(-1, &ws, unix.WALL, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if err == unix.ECHILD {
				break
			}
			return 0, err
		}
		if ws.Exited() || ws.Signaled() {
			delete(live, pid)
			if pid == root {
				if ws.Signaled() {
					exit = 128 + int(ws.Signal())
				} else {
					exit = ws.ExitStatus()
				}
				break
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		if !live[pid] {
			live[pid] = true // a new tracee (auto-attached child) announcing itself
		}
		sig := ws.StopSignal()
		event := int(ws) >> 16
		switch {
		case sig == unix.SIGTRAP && event == unix.PTRACE_EVENT_EXEC:
			e := describe(pid)
			if t.Skip != nil && t.Skip(e) {
				unix.PtraceCont(pid, 0)
				continue
			}
			if t.Decide != nil && t.Decide(e) == Deny {
				unix.Kill(pid, unix.SIGKILL)
			}
			unix.PtraceCont(pid, 0)
		case event != 0:
			// clone/fork/vfork notification on the parent
			unix.PtraceCont(pid, 0)
		case sig == unix.SIGTRAP || sig == unix.SIGSTOP:
			// an initial stop of a new child, or a trap of ours: swallow
			unix.PtraceCont(pid, 0)
		default:
			// a real signal for the tracee: deliver it
			unix.PtraceCont(pid, int(sig))
		}
	}
	if exit < 0 {
		return 0, errors.New("lost the agent process")
	}
	return exit, nil
}

func describe(pid int) Exec {
	e := Exec{PID: pid}
	p := "/proc/" + strconv.Itoa(pid)
	e.Exe, _ = os.Readlink(p + "/exe")
	e.Cwd, _ = os.Readlink(p + "/cwd")
	if b, err := os.ReadFile(p + "/cmdline"); err == nil {
		for _, a := range bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0}) {
			e.Argv = append(e.Argv, string(a))
		}
	}
	return e
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true}

// CommandLine is the resource a policy sees for an exec: for a shell
// running `-c "..."` it is that string, otherwise the command line with
// argv[0] reduced to its base name. Policies match it as "shell:<line>".
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

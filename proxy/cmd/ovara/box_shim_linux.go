//go:build linux

package main

// The exec shim: `box-init -exec-shim [-allow-userns] [-allow-debuggers] --
// PROGRAM ARGS...`. It is how the VM guest (box_vm_guest.go) and a tier 2
// container (boxinit.go) start the agent, so that both put the same seccomp
// filter (internal/boxseccomp) on the agent that tier 1 does (box_tier1.go
// installs it itself, in the one process that becomes the agent).
//
// The filter has to be installed by the agent's own process, as the agent's
// user, after no_new_privs and before its first instruction: nothing above it
// may be under it, or the host-side tracer (box-init, PID 1 of a container)
// could not ptrace. So box-init starts the shim in the agent's place; the
// shim installs the filter and execs the agent, keeping the process id. The
// command gate sees the shim's exec first and is told to let that one pass
// (shimSkipper); the agent's own exec comes next and is checked like any other.

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/boxseccomp"
)

const execShimFlag = "-exec-shim"

// shimArgv is the command line that starts argv through the shim, run from
// self (this binary).
func shimArgv(self string, o boxseccomp.Options, argv []string) []string {
	out := []string{self, boxInitCmd, execShimFlag}
	if o.AllowUserNamespaces {
		out = append(out, "-allow-userns")
	}
	if o.AllowDebuggers {
		out = append(out, "-allow-debuggers")
	}
	out = append(out, "--")
	return append(out, argv...)
}

// shimSkipper returns a Tracer.Skip that lets exactly one exec through
// unasked, the first, and only if it is the shim: a program that later runs
// the shim itself is checked like any other.
func shimSkipper() func(boxgate.Exec) bool {
	seen := false
	return func(e boxgate.Exec) bool {
		if seen {
			return false
		}
		seen = true
		return len(e.Argv) >= 3 && e.Argv[1] == boxInitCmd && e.Argv[2] == execShimFlag
	}
}

// runExecShim is the shim. Running as the agent's user it installs the filter
// (which also sets no_new_privs, so a set-uid program gives the agent
// nothing), then becomes the agent. It fails closed: if the filter cannot be
// installed the agent is not started.
func runExecShim(argv []string, o boxseccomp.Options) error {
	if len(argv) == 0 {
		return errors.New("box-init -exec-shim: no agent command")
	}
	if os.Geteuid() == 0 {
		return errors.New("box-init -exec-shim: refusing to run the agent as root")
	}
	// Install locks this goroutine to its thread, and the exec below must be
	// made from it: see boxseccomp.Install.
	if err := boxseccomp.Install(o); err != nil {
		return fmt.Errorf("box-init -exec-shim: %w", err)
	}
	env := os.Environ()
	path, err := lookPathIn(argv[0], env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(argv[0]), err)
		os.Exit(127)
	}
	err = syscall.Exec(path, argv, env) //nolint:gosec // the agent command the person gave
	fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(argv[0]), err)
	os.Exit(126)
	return nil
}

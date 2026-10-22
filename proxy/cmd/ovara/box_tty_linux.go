//go:build linux

package main

// The agent in front of a person's terminal.
//
// Tier 1 and tier 2 start the agent (or the docker client that runs it) in a
// process group of its own, so that a signal to `ovara box` can be forwarded to
// that whole group. On a terminal that group is a BACKGROUND group of the
// session: the first read of the terminal stops it with SIGTTIN, and a TUI
// agent (`ovara box ./repo -- <agent>`, the documented way in) sits at a
// prompt that never gets a key. Piped runs, which is all CI does, are
// unaffected, which is how this went unseen.
//
// So while the agent runs it takes the terminal, as a shell does for a job it
// runs in the foreground: Ctrl-C and Ctrl-Z then go to the agent, as they would
// without Ovara, and `ovara box` takes the terminal back when the agent is done,
// before it has anything to ask the person (the commit-back review).

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// foregroundTTY makes attr start its process in the terminal's foreground, if
// this run is attached to a terminal that `ovara box` itself is in the foreground
// of; it returns what to call once the process is gone to take the terminal
// back. Anywhere else (piped, redirected, run in the background of a shell, no
// controlling terminal) it changes nothing and returns a no-op.
func foregroundTTY(attr *syscall.SysProcAttr) (restore func()) {
	fd := int(os.Stdin.Fd())
	if !isTerminal(os.Stdin) {
		return func() {}
	}
	// TIOCGPGRP works only on the caller's controlling terminal and says which
	// group has it; if that is not ours, we are not the one to hand it on
	fg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || fg != syscall.Getpgrp() {
		return func() {}
	}
	attr.Setpgid = true
	attr.Foreground = true
	attr.Ctty = fd
	// While the agent holds the terminal this process is in the background of
	// it: with SIGTTOU ignored its own messages still reach the screen even if
	// the terminal is set to stop background writers, and it may take the
	// terminal back below.
	signal.Ignore(syscall.SIGTTOU)
	return func() {
		_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, syscall.Getpgrp())
		signal.Reset(syscall.SIGTTOU)
	}
}

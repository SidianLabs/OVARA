//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// vmWritevSelf makes a harmless process_vm_writev call (zero iovecs) against
// this process. Without the box filter it returns 0; with it, EPERM.
func vmWritevSelf() unix.Errno {
	_, _, errno := unix.Syscall6(unix.SYS_PROCESS_VM_WRITEV, uintptr(os.Getpid()), 0, 0, 0, 0, 0)
	return errno
}

// TestBoxSeccompBlocksCrossProcessMemory runs the filter in a child (installing
// it in the test process would bind the whole run): before it, process_vm_writev
// succeeds; after it, the same call and ptrace are refused, while ordinary
// execution continues.
func TestBoxSeccompBlocksCrossProcessMemory(t *testing.T) {
	if os.Getenv("OVARA_SECCOMP_HELPER") == "1" {
		// child: prove the syscall works, install the filter, prove it is
		// now refused, and that we are still running afterwards.
		if errno := vmWritevSelf(); errno != 0 {
			os.Stderr.WriteString("before: process_vm_writev errno " + errno.Error() + "\n")
			os.Exit(10)
		}
		if err := installBoxSeccomp(); err != nil {
			os.Stderr.WriteString("install: " + err.Error() + "\n")
			os.Exit(11)
		}
		if errno := vmWritevSelf(); errno != unix.EPERM {
			os.Stderr.WriteString("after: process_vm_writev errno " + errno.Error() + "\n")
			os.Exit(12)
		}
		if _, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_ATTACH), uintptr(os.Getpid()), 0, 0, 0, 0); errno != unix.EPERM {
			os.Stderr.WriteString("after: ptrace errno " + errno.Error() + "\n")
			os.Exit(13)
		}
		os.Exit(0)
	}
	// no_new_privs is a precondition for an unprivileged seccomp filter; the
	// child sets it the same way box-init does.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err == nil {
		// setting it in the parent is harmless and lets the child inherit it
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestBoxSeccompBlocksCrossProcessMemory") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), "OVARA_SECCOMP_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
}

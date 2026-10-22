//go:build linux

package boxseccomp

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Install builds the filter for this machine's architecture and attaches it
// to the calling process, all of its threads.
//
// It sets no_new_privs first (which it also needs to install a filter without
// CAP_SYS_ADMIN), locks the calling goroutine to its thread and leaves it
// locked. The caller must then exec the agent from this same goroutine
// without starting anything in between: when a thread other than the main one
// execs, it becomes the process, and the filter that matters is the one on
// that thread. TSYNC puts the filter on every thread anyway, but only where
// the kernel supports it (it does not under some sandboxes), so the
// exec-on-the-installing-thread rule is what the fallback rests on.
//
// It fails closed. On an architecture without a program (anything but
// amd64 and arm64), or if the kernel will not take the filter, or if the
// filter is not in force afterwards, it returns an error and the caller must
// not start the agent: running it without the filter is the failure this
// package exists to prevent.
func Install(o Options) error {
	a, ok := ArchFor(runtime.GOARCH)
	if !ok {
		return fmt.Errorf("the box seccomp filter does not exist for GOARCH=%s (the box's release architectures are amd64 and arm64), so the agent is not started", runtime.GOARCH)
	}
	prog, err := Build(a, Rules(o))
	if err != nil {
		return err
	}
	return install(prog)
}

func install(prog []insn) error {
	if len(prog) == 0 || len(prog) > unix.BPF_MAXINSNS {
		return fmt.Errorf("boxseccomp: a program of %d instructions", len(prog)) // also keeps the uint16 Len below honest
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]} //nolint:gosec // bounded by BPF_MAXINSNS above
	call := func(flags uintptr) (uintptr, unix.Errno) {
		r, _, errno := unix.Syscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_SET_MODE_FILTER), flags, uintptr(unsafe.Pointer(&fprog)))
		return r, errno
	}
	r, errno := call(unix.SECCOMP_FILTER_FLAG_TSYNC)
	if errno == unix.EINVAL {
		// no TSYNC here (gVisor and a few other sandboxes): the filter binds
		// this thread, which is the one that will exec the agent
		r, errno = call(0)
	}
	runtime.KeepAlive(prog)
	if errno != 0 {
		return fmt.Errorf("installing the box seccomp filter: %w", errno)
	}
	if r != 0 {
		// with TSYNC a positive result is the id of a thread that could not
		// be brought under the filter
		return fmt.Errorf("installing the box seccomp filter: thread %d could not be synchronised", r)
	}
	mode, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("checking the box seccomp filter: %w", err)
	}
	if mode != unix.SECCOMP_MODE_FILTER {
		return errors.New("the box seccomp filter is not in force after installing it")
	}
	return nil
}

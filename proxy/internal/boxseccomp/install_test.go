//go:build linux

package boxseccomp

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The kernel tests install the real filter in a re-exec'd copy of the test
// binary (installing it here would bind the whole test run) and ask the real
// kernel. Each probe uses arguments whose NATIVE answer differs from the
// denial, so the test proves the filter caused the refusal rather than the
// kernel or the host already refusing. A probe whose native answer happens
// to equal the denial on this host is reported and skipped, not counted.

const modeExec = "exec" // the helper mode that execs a shell after installing the filter

func TestMain(m *testing.M) {
	if mode := os.Getenv("BOXSECCOMP_HELPER"); mode != "" {
		os.Exit(helperMain(mode))
	}
	os.Exit(m.Run())
}

func sys(nr uintptr, args ...uintptr) unix.Errno {
	var x [6]uintptr
	copy(x[:], args)
	_, _, e := unix.Syscall6(nr, x[0], x[1], x[2], x[3], x[4], x[5])
	return e
}

type kprobe struct {
	name string
	call func() unix.Errno
	deny string // the errno the filter returns
	lift Lift
	soft bool // the native answer may equal the denial on some hosts: skip, do not fail
}

func kernelProbes() []kprobe {
	const hi = 1 << 40 // garbage in the high word of a flag argument
	ps := []kprobe{
		{"ptrace", func() unix.Errno { return sys(unix.SYS_PTRACE, unix.PTRACE_PEEKDATA, 1<<22, 0, 0) }, "EPERM", LiftDebug, false},
		{"process_vm_readv", func() unix.Errno { return sys(unix.SYS_PROCESS_VM_READV, 1<<22, 0, 0, 0, 0, 0) }, "EPERM", LiftDebug, true},
		{"process_vm_writev", func() unix.Errno { return sys(unix.SYS_PROCESS_VM_WRITEV, 1<<22, 0, 0, 0, 0, 0) }, "EPERM", LiftDebug, true},
		{"perf_event_open", func() unix.Errno { return sys(unix.SYS_PERF_EVENT_OPEN, 0, 0, ^uintptr(0), ^uintptr(0), 0) }, "EPERM", LiftDebug, false},
		{"pidfd_getfd", func() unix.Errno { return sys(unix.SYS_PIDFD_GETFD, ^uintptr(0), ^uintptr(0), 0) }, "EPERM", LiftNone, false},
		{"clone3", func() unix.Errno { return sys(unix.SYS_CLONE3, 0, 0) }, "ENOSYS", LiftNone, false},
		{"setns", func() unix.Errno { return sys(unix.SYS_SETNS, ^uintptr(0), 0) }, "EPERM", LiftNone, false},
		{"unshare (garbage high word)", func() unix.Errno { return sys(unix.SYS_UNSHARE, unix.CLONE_NEWUSER|hi) }, "EPERM", LiftUserNS, false},
		{"unshare newnet (garbage high word)", func() unix.Errno { return sys(unix.SYS_UNSHARE, unix.CLONE_NEWNET|unix.CLONE_NEWNS|hi) }, "EPERM", LiftUserNS, false},
		{"socket AF_PACKET", func() unix.Errno { return socketErr(unix.AF_PACKET, unix.SOCK_RAW, 0) }, "EAFNOSUPPORT", LiftNone, false},
		{"socketpair AF_PACKET", func() unix.Errno { return sys(unix.SYS_SOCKETPAIR, unix.AF_PACKET, unix.SOCK_RAW, 0, 0) }, "EAFNOSUPPORT", LiftNone, false},
		{"socket NETLINK_NETFILTER", func() unix.Errno { return socketErr(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER) }, "EPROTONOSUPPORT", LiftNone, true},
		{"io_uring_setup", func() unix.Errno { return sys(unix.SYS_IO_URING_SETUP, 0, 0) }, "ENOSYS", LiftNone, true},
		{"bpf", func() unix.Errno { return sys(unix.SYS_BPF, 0xffff, 0, 0) }, "EPERM", LiftNone, false},
		{"userfaultfd", func() unix.Errno { return sys(unix.SYS_USERFAULTFD, 0x7fffffff) }, "EPERM", LiftNone, false},
		{"keyctl", func() unix.Errno { return sys(unix.SYS_KEYCTL, 0xffff) }, "EPERM", LiftNone, false},
		{"reboot (bad magic: harmless natively)", func() unix.Errno { return sys(unix.SYS_REBOOT, 0, 0, 0, 0) }, "EPERM", LiftNone, false},
		{"open_by_handle_at", func() unix.Errno { return sys(unix.SYS_OPEN_BY_HANDLE_AT, ^uintptr(0), 0, 0) }, "EPERM", LiftNone, true},
		{"mount", func() unix.Errno { return sys(unix.SYS_MOUNT, 0, 0, 0, 0, 0) }, "EPERM", LiftUserNS, true},
	}
	if runtime.GOARCH == nameAmd64 {
		ps = append(ps,
			kprobe{"modify_ldt", func() unix.Errno { return sys(154, 0xffff, 0, 0) }, "EPERM", LiftNone, false},
			kprobe{"iopl (level 99: harmless natively)", func() unix.Errno { return sys(172, 99) }, "EPERM", LiftNone, false},
		)
	}
	return ps
}

func socketErr(domain, typ, proto int) unix.Errno {
	r, _, e := unix.Syscall(unix.SYS_SOCKET, uintptr(domain), uintptr(typ), uintptr(proto))
	if e == 0 {
		unix.Close(int(r))
	}
	return e
}

func errName(e unix.Errno) string {
	switch e {
	case 0:
		return "ok"
	case unix.EPERM:
		return "EPERM"
	case unix.ENOSYS:
		return "ENOSYS"
	case unix.EAFNOSUPPORT:
		return "EAFNOSUPPORT"
	case unix.EPROTONOSUPPORT:
		return "EPROTONOSUPPORT"
	}
	return e.Error()
}

// helperMain is the child: install the filter for BOXSECCOMP_OPTS (or none),
// then print what the kernel says to every probe and every control as JSON.
func helperMain(mode string) int {
	opts := os.Getenv("BOXSECCOMP_OPTS")
	if opts != "none" {
		o := Options{AllowUserNamespaces: opts == "userns" || opts == "both", AllowDebuggers: opts == "debug" || opts == "both"}
		runtime.LockOSThread()
		if err := Install(o); err != nil {
			os.Stderr.WriteString("INSTALL: " + err.Error() + "\n")
			return 10
		}
	}
	out := map[string]string{}
	switch mode {
	case "probes":
		for _, p := range kernelProbes() {
			out[p.name] = errName(p.call())
		}
		out = liveControls(out)
	case "threads":
		// the filter must hold on threads other than the installing one
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runtime.LockOSThread() // a thread of its own, started after the filter was installed or before it
				e := errName(sys(unix.SYS_PIDFD_GETFD, ^uintptr(0), ^uintptr(0), 0))
				mu.Lock()
				out["thread"+string(rune('a'+i))] = e
				mu.Unlock()
			}()
		}
		wg.Wait()
	case modeExec:
		// the filter must survive exec; /proc/self/status and a real unshare(1) say so
		script := `grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status
if command -v unshare >/dev/null 2>&1; then unshare -Ur true 2>/dev/null && echo userns=yes || echo userns=no; else echo userns=skip; fi
if command -v python3 >/dev/null 2>&1 && [ "$(uname -m)" = x86_64 ]; then python3 - <<'PY'
import ctypes, mmap, os
code = bytes([0xb8,0x14,0x00,0x00,0x00, 0xcd,0x80, 0xc3])   # mov eax,20 (i386 getpid); int 0x80; ret
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
m.write(code)
r = ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()
print("int80=" + ("worked" if r == os.getpid() else "denied"))
PY
else echo int80=skip; fi`
		err := syscall.Exec("/bin/sh", []string{"sh", "-c", script}, os.Environ()) //nolint:gosec // re-exec of this test binary
		os.Stderr.WriteString("exec: " + err.Error() + "\n")
		return 11
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
	return 0
}

// liveControls: what must work under the filter, run in the child after Install.
func liveControls(out map[string]string) map[string]string {
	ok := func(name string, err error) {
		if err != nil {
			out["control/"+name] = err.Error()
		} else {
			out["control/"+name] = "ok"
		}
	}
	for _, s := range []struct {
		name    string
		d, t, p int
	}{{"unix", unix.AF_UNIX, unix.SOCK_STREAM, 0}, {"inet", unix.AF_INET, unix.SOCK_STREAM, 0}, {"inet6", unix.AF_INET6, unix.SOCK_DGRAM, 0},
		{"netlink-route", unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE}} {
		fd, err := unix.Socket(s.d, s.t, s.p)
		if err == nil {
			unix.Close(fd)
		}
		if s.name == "inet6" && errors.Is(err, unix.EAFNOSUPPORT) {
			continue // a kernel without IPv6 says so itself
		}
		ok("socket-"+s.name, err)
	}
	if fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0); err == nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		ok("socketpair-unix", nil)
	} else {
		ok("socketpair-unix", err)
	}
	_, err := net.Interfaces() // uses NETLINK_ROUTE
	ok("net.Interfaces", err)
	ok("fork-exec", exec.Command("true").Run())
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ { // 64 threads: clone with thread flags
		wg.Add(1)
		go func() { defer wg.Done(); runtime.LockOSThread(); _ = unix.Getpid() }()
	}
	wg.Wait()
	ok("threads", nil)
	r, w, err := os.Pipe() // splice between a pipe and a socket pair must not be refused
	if err == nil {
		_, _, e := unix.Syscall6(unix.SYS_SPLICE, r.Fd(), 0, w.Fd(), 0, 1, 0)
		if e == unix.EPERM || e == unix.ENOSYS {
			err = e
		}
		r.Close()
		w.Close()
	}
	ok("splice-not-refused", err)
	return out
}

func runHelper(t *testing.T, mode, opts string) (map[string]string, string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // re-exec of this test binary
	cmd.Env = append(os.Environ(), "BOXSECCOMP_HELPER="+mode, "BOXSECCOMP_OPTS="+opts)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	res := map[string]string{}
	if err == nil && mode != modeExec {
		if jerr := json.Unmarshal(b, &res); jerr != nil {
			t.Fatalf("helper output %q: %v", b, jerr)
		}
	}
	if mode == modeExec {
		return map[string]string{"raw": string(b)}, stderr.String(), err
	}
	return res, stderr.String(), err
}

// skipIfSeccompUnavailable skips (or fails, when CI says seccomp must work)
// if this host will not let a process install a filter at all.
func skipIfSeccompUnavailable(t *testing.T, stderr string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(stderr, "INSTALL:") && os.Getenv("OVARA_REQUIRE_SECCOMP_TEST") != "1" {
		t.Skipf("this host will not install a seccomp filter: %s", strings.TrimSpace(stderr))
	}
	t.Fatalf("helper: %v\n%s", err, stderr)
}

func TestInstalledFilterAnswersTheKernel(t *testing.T) {
	native, stderr, err := runHelper(t, "probes", "none")
	if err != nil {
		t.Fatalf("helper without the filter: %v\n%s", err, stderr)
	}
	discriminating := 0
	for _, os := range optionSets {
		got, stderr, err := runHelper(t, "probes", os.name)
		skipIfSeccompUnavailable(t, stderr, err)
		for _, p := range kernelProbes() {
			lifted := (p.lift == LiftUserNS && os.opts.AllowUserNamespaces) || (p.lift == LiftDebug && os.opts.AllowDebuggers)
			if lifted {
				if got[p.name] != native[p.name] {
					t.Errorf("%s: %s: with the opt-out the kernel's own answer is %s, got %s", os.name, p.name, native[p.name], got[p.name])
				}
				continue
			}
			if native[p.name] == p.deny {
				if !p.soft {
					t.Errorf("%s: %s: the probe does not discriminate: the kernel itself already answers %s", os.name, p.name, p.deny)
				} else {
					t.Logf("%s: %s: skipped, this host's kernel already answers %s", os.name, p.name, p.deny)
				}
				continue
			}
			if os.name == "default" {
				discriminating++
			}
			if got[p.name] != p.deny {
				t.Errorf("%s: %s: got %s, want %s (the kernel's own answer is %s)", os.name, p.name, got[p.name], p.deny, native[p.name])
			}
		}
		for k, v := range got {
			if strings.HasPrefix(k, "control/") && v != "ok" {
				t.Errorf("%s: %s failed under the filter: %s", os.name, k, v)
			}
		}
	}
	if discriminating < 12 {
		t.Errorf("only %d probes discriminate on this host; the kernel test proves too little", discriminating)
	}
}

func TestFilterBindsEveryThread(t *testing.T) {
	got, stderr, err := runHelper(t, "threads", "default")
	skipIfSeccompUnavailable(t, stderr, err)
	if len(got) != 16 {
		t.Fatalf("%d threads reported", len(got))
	}
	for k, v := range got {
		if v != "EPERM" {
			t.Errorf("%s: pidfd_getfd answered %s, want EPERM (the filter did not reach this thread)", k, v)
		}
	}
}

func TestFilterSurvivesExec(t *testing.T) {
	for _, opts := range []string{"default", "userns"} {
		got, stderr, err := runHelper(t, modeExec, opts)
		skipIfSeccompUnavailable(t, stderr, err)
		raw := got["raw"]
		for _, w := range []string{"Seccomp:\t2", "NoNewPrivs:\t1"} {
			if !strings.Contains(raw, w) {
				t.Errorf("%s: exec'd program lacks %q:\n%s", opts, w, raw)
			}
		}
		if opts == "default" {
			if strings.Contains(raw, "userns=yes") {
				t.Errorf("unshare -Ur worked under the filter:\n%s", raw)
			}
			if strings.Contains(raw, "int80=worked") {
				t.Errorf("the i386 ABI is reachable through int 0x80:\n%s", raw)
			}
			if runtime.GOARCH == nameAmd64 && !strings.Contains(raw, "int80=denied") && !strings.Contains(raw, "int80=skip") {
				t.Errorf("no int 0x80 verdict:\n%s", raw)
			}
		}
	}
}

func TestInstallRefusesAnImpossibleProgram(t *testing.T) {
	if err := install(nil); err == nil {
		t.Error("an empty program installed")
	}
	if err := install(make([]insn, unix.BPF_MAXINSNS+1)); err == nil {
		t.Error("a 4097-instruction program installed")
	}
}

//go:build linux

package boxseccomp

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The specification: what the filter must do, written by hand and NOT derived
// from Table. Dropping or weakening any Table entry must flip a probe here
// (TestEveryRuleAndClauseIsLoadBearing checks that it does).

const allow = "ALLOW"

type probe struct {
	sys  string // call name
	args [6]uint64
	want string // "ALLOW" or an errno name
	lift Lift   // an opt-out that makes the answer ALLOW
	note string
}

func a(args ...uint64) [6]uint64 {
	var r [6]uint64
	copy(r[:], args)
	return r
}

// signExt is a 32-bit flag word sign-extended into 64 bits, as C compilers do
// for an int passed to a long parameter.
func signExt(v uint32) uint64 { return uint64(int64(int32(v))) } //nolint:gosec // test arithmetic on small bounded values

const (
	sigchld = 17
	// glibc's and Go's thread flags: CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID
	threadFlags = 0x3d0f00
)

var spec = []probe{
	// --- one box process reaching into another
	{"ptrace", a(unix.PTRACE_PEEKDATA, 1<<22), "EPERM", LiftDebug, ""},
	{"ptrace", a(unix.PTRACE_ATTACH, 2), "EPERM", LiftDebug, ""},
	{"process_vm_readv", a(1), "EPERM", LiftDebug, ""},
	{"process_vm_writev", a(1), "EPERM", LiftDebug, ""},
	{"perf_event_open", a(0), "EPERM", LiftDebug, ""},
	{"pidfd_getfd", a(3, 3), "EPERM", LiftNone, ""},
	{"kcmp", a(1, 2, 0), "EPERM", LiftNone, ""},
	{"process_madvise", a(3), "EPERM", LiftNone, ""},

	// --- namespaces
	{"clone3", a(0, 0), "ENOSYS", LiftNone, "its flags are in memory: libc falls back to clone"},
	{"setns", a(^uint64(0), 0), "EPERM", LiftNone, ""},
	{"unshare", a(unix.CLONE_NEWUSER), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWUSER | unix.CLONE_NEWNET), "EPERM", LiftUserNS, "unshare -Urn"},
	{"unshare", a(unix.CLONE_NEWNS), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWCGROUP), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWUTS), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWIPC), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWPID), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWNET), "EPERM", LiftUserNS, ""},
	{"unshare", a(unix.CLONE_NEWTIME), "EPERM", LiftUserNS, "a namespace in unshare, the exit signal in clone"},
	{"unshare", a(unix.CLONE_FS), allow, LiftNone, ""},
	{"unshare", a(unix.CLONE_FILES), allow, LiftNone, ""},
	{"unshare", a(0), allow, LiftNone, ""},
	{"unshare", a(1 << 60), allow, LiftNone, "the high word is the kernel's business"},
	{"clone", a(unix.CLONE_NEWUSER | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWNS | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWCGROUP | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWUTS | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWIPC | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWPID | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWNET | sigchld), "EPERM", LiftUserNS, ""},
	{"clone", a(unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | sigchld), "EPERM", LiftUserNS, "a browser's zygote flags"},
	{"clone", a(threadFlags), allow, LiftNone, "every thread of every runtime"},
	{"clone", a(sigchld), allow, LiftNone, "fork on arm64"},
	{"clone", a(unix.CLONE_VM | 0x4000 | sigchld), allow, LiftNone, "posix_spawn (CLONE_VFORK 0x4000)"},
	{"clone", a(signExt(0x80000000 | sigchld)), allow, LiftNone, "CLONE_IO sign-extended into the high word"},
	{"clone", a(0x80), allow, LiftNone, "bit 7 is the exit signal in clone, not CLONE_NEWTIME"},

	// --- sockets: the domain is argument 0, an int
	{"socket", a(unix.AF_ALG, unix.SOCK_SEQPACKET), "EAFNOSUPPORT", LiftNone, "Copy Fail, CVE-2025-39964"},
	{"socket", a(unix.AF_ALG, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK), "EAFNOSUPPORT", LiftNone, "type flags must not matter"},
	{"socket", a(unix.AF_RDS, unix.SOCK_SEQPACKET), "EAFNOSUPPORT", LiftNone, "PinTheft"},
	{"socket", a(unix.AF_TIPC, unix.SOCK_RDM), "EAFNOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_KEY, unix.SOCK_RAW), "EAFNOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_PACKET, unix.SOCK_RAW), "EAFNOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_VSOCK, unix.SOCK_STREAM), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_KEY, unix.SOCK_RAW), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_PACKET, unix.SOCK_RAW), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_RDS, unix.SOCK_SEQPACKET), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_TIPC, unix.SOCK_RDM), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_ALG, unix.SOCK_SEQPACKET), "EAFNOSUPPORT", LiftNone, ""},
	{"socketpair", a(unix.AF_VSOCK, unix.SOCK_STREAM), "EAFNOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER), "EPROTONOSUPPORT", LiftNone, "a two-term clause"},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_XFRM), "EPROTONOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_AUDIT), "EPROTONOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_CRYPTO), "EPROTONOSUPPORT", LiftNone, ""},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE), allow, LiftNone, "Go net.Interfaces, getaddrinfo"},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_KOBJECT_UEVENT), allow, LiftNone, ""},
	{"socket", a(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_GENERIC), allow, LiftNone, ""},
	{"socket", a(unix.AF_UNIX, unix.SOCK_STREAM), allow, LiftNone, ""},
	{"socket", a(unix.AF_INET, unix.SOCK_STREAM), allow, LiftNone, ""},
	{"socket", a(unix.AF_INET6, unix.SOCK_DGRAM), allow, LiftNone, ""},
	{"socketpair", a(unix.AF_UNIX, unix.SOCK_STREAM), allow, LiftNone, ""},

	// --- kernel facilities
	{"io_uring_setup", a(8), "ENOSYS", LiftNone, "what a kernel without it says: libuv falls back"},
	{"io_uring_enter", a(3), "ENOSYS", LiftNone, ""},
	{"io_uring_register", a(3), "ENOSYS", LiftNone, ""},
	{"bpf", a(0), "EPERM", LiftNone, ""},
	{"userfaultfd", a(0), "EPERM", LiftNone, ""},
	{"keyctl", a(0), "EPERM", LiftNone, ""},
	{"add_key", a(0), "EPERM", LiftNone, ""},
	{"request_key", a(0), "EPERM", LiftNone, ""},
	{"kexec_load", a(0), "EPERM", LiftNone, ""},
	{"kexec_file_load", a(0), "EPERM", LiftNone, ""},
	{"init_module", a(0), "EPERM", LiftNone, ""},
	{"finit_module", a(0), "EPERM", LiftNone, ""},
	{"delete_module", a(0), "EPERM", LiftNone, ""},
	{"reboot", a(0), "EPERM", LiftNone, ""},
	{"open_by_handle_at", a(0), "EPERM", LiftNone, ""},
	{"name_to_handle_at", a(0), "EPERM", LiftNone, ""},

	// --- the mount family, which lifts with the namespaces
	{"mount", a(0), "EPERM", LiftUserNS, ""}, {"umount2", a(0), "EPERM", LiftUserNS, ""},
	{"pivot_root", a(0), "EPERM", LiftUserNS, ""}, {"chroot", a(0), "EPERM", LiftUserNS, ""},
	{"open_tree", a(0), "EPERM", LiftUserNS, ""}, {"open_tree_attr", a(0), "EPERM", LiftUserNS, ""},
	{"move_mount", a(0), "EPERM", LiftUserNS, ""}, {"fsopen", a(0), "EPERM", LiftUserNS, ""},
	{"fsconfig", a(0), "EPERM", LiftUserNS, ""}, {"fsmount", a(0), "EPERM", LiftUserNS, ""},
	{"fspick", a(0), "EPERM", LiftUserNS, ""}, {"mount_setattr", a(0), "EPERM", LiftUserNS, ""},

	// --- capability-gated administration
	{"swapon", a(0), "EPERM", LiftNone, ""}, {"swapoff", a(0), "EPERM", LiftNone, ""}, {"acct", a(0), "EPERM", LiftNone, ""},
	{"quotactl", a(0), "EPERM", LiftNone, ""}, {"quotactl_fd", a(0), "EPERM", LiftNone, ""},
	{"lookup_dcookie", a(0), "EPERM", LiftNone, ""}, {"syslog", a(0), "EPERM", LiftNone, ""},
	{"settimeofday", a(0), "EPERM", LiftNone, ""}, {"clock_settime", a(0), "EPERM", LiftNone, ""},
	{"sethostname", a(0), "EPERM", LiftUserNS, "a UTS namespace of one's own is where it is useful"},
	{"setdomainname", a(0), "EPERM", LiftUserNS, ""},

	// --- x86 only
	{"modify_ldt", a(0), "EPERM", LiftNone, "amd64 only"},
	{"iopl", a(0), "EPERM", LiftNone, "amd64 only"},
	{"ioperm", a(0), "EPERM", LiftNone, "amd64 only"},
}

// controls: calls that must keep working under every option set, on both
// architectures. They include the ones a tidy-minded deny list would be tempted
// to add and that real programs fail without.
var controls = []string{
	"getpid", "gettid", "read", "write", "openat", "close", "execve", "execveat", "mmap", "mprotect", "munmap", "futex",
	"epoll_create1", "epoll_ctl", "eventfd2", "memfd_create", "pidfd_open", "pidfd_send_signal", "wait4", "waitid", "prctl",
	"seccomp", "close_range", "copy_file_range", "splice", "sendfile", "tee", "vmsplice", "getrandom", "rseq",
	"landlock_create_ruleset", "exit_group", "rt_sigaction", "ioctl", "fcntl", "connect", "bind", "listen", "accept4", "sendmsg",
	"recvmsg", "setsockopt", "getsockopt", "setuid", "setresuid", "capset", "mincore", "memfd_secret", "personality",
	"getpriority", "clock_gettime", "clock_nanosleep", "nanosleep", "timerfd_create", "inotify_init1", "fanotify_init",
	"adjtimex", "clock_adjtime", // their read-only form is open to everyone
	"setrlimit", "prlimit64", "sched_setaffinity", "madvise", "mlock", "membarrier", "statx", "getdents64", "unlinkat",
}

var optionSets = []struct {
	name string
	opts Options
}{
	{"default", Options{}},
	{"userns", Options{AllowUserNamespaces: true}},
	{"debug", Options{AllowDebuggers: true}},
	{"both", Options{AllowUserNamespaces: true, AllowDebuggers: true}},
}

func legacyOnly(p probe) bool { return strings.Contains(p.note, "amd64 only") }

func want(p probe, o Options) string {
	if (p.lift == LiftUserNS && o.AllowUserNamespaces) || (p.lift == LiftDebug && o.AllowDebuggers) {
		return allow
	}
	return p.want
}

func errnoName(e string) string {
	if e == allow {
		return allow
	}
	m := map[string]unix.Errno{"EPERM": unix.EPERM, "ENOSYS": unix.ENOSYS, "EAFNOSUPPORT": unix.EAFNOSUPPORT, "EPROTONOSUPPORT": unix.EPROTONOSUPPORT}
	return m[e].Error()
}

func lookup(t testing.TB, arch, name string) (uint32, bool) {
	if n, ok := notInXSys[name]; ok {
		return n, true
	}
	n, ok := xsysNumbers(t, arch)[strings.ToUpper(name)]
	return n, ok
}

func sd(arch Arch, nr uint32, args [6]uint64) seccompData {
	return seccompData{Nr: int32(nr), Arch: arch.Audit, Args: args} //nolint:gosec // test arithmetic on small bounded values
}

func build(t testing.TB, arch Arch, table []Rule, o Options) []unix.SockFilter {
	t.Helper()
	prog, err := Build(arch, rulesFrom(table, o))
	if err != nil {
		t.Fatalf("%s: %v", arch.Name, err)
	}
	if err := validate(prog); err != nil {
		t.Fatalf("%s: %v", arch.Name, err)
	}
	return prog
}

// evalSpec runs every probe, and its twin with garbage in the high word of
// every argument, against prog. It returns the failures and every answer.
func evalSpec(t testing.TB, archName string, prog []unix.SockFilter, o Options) (fails []string, results map[string]string) {
	t.Helper()
	arch := archOf(archName)
	results = map[string]string{}
	for i, p := range spec {
		nr, ok := lookup(t, archName, p.sys)
		if !ok {
			if legacyOnly(p) {
				continue
			}
			t.Fatalf("%s has no call %s in x/sys", archName, p.sys)
		}
		if legacyOnly(p) && archName != nameAmd64 {
			t.Fatalf("%s must not exist on %s", p.sys, archName)
		}
		for _, garbage := range []bool{false, true} {
			args := p.args
			if garbage {
				for j := range args {
					args[j] |= 0xdeadbeef << 32 // the kernel ignores this half of int and flag arguments
				}
			}
			v, err := run(prog, sd(arch, nr, args))
			if err != nil {
				t.Fatalf("%s %s: %v", archName, p.sys, err)
			}
			got := verdictName(v)
			results[fmt.Sprintf("%d/%s/%v", i, p.sys, garbage)] = got
			if w := errnoName(want(p, o)); got != w {
				fails = append(fails, fmt.Sprintf("%s %s%v (garbage high words: %v): got %s, want %s", archName, p.sys, p.args, garbage, got, w))
			}
		}
	}
	for _, c := range controls {
		nr, ok := lookup(t, archName, c)
		if !ok {
			continue
		}
		v, _ := run(prog, sd(arch, nr, a(1, 2, 3, 4, 5, 6)))
		results["control/"+c] = verdictName(v)
		if v != retAllow {
			fails = append(fails, fmt.Sprintf("%s control %s: got %s, want ALLOW", archName, c, verdictName(v)))
		}
	}
	return fails, results
}

func TestSpecBothArchesAllOptions(t *testing.T) {
	for _, an := range bothArches {
		for _, os := range optionSets {
			prog := build(t, archOf(an), Table, os.opts)
			t.Logf("%s %s: %d instructions", an, os.name, len(prog))
			if fails, _ := evalSpec(t, an, prog, os.opts); len(fails) > 0 {
				t.Errorf("%s %s:\n%s", an, os.name, strings.Join(fails, "\n"))
			}
		}
	}
}

// The controls have to exist on at least one architecture each, or a typo
// would turn a control into a silent no-op.
func TestControlsAreRealCalls(t *testing.T) {
	for _, c := range controls {
		_, amd := lookup(t, "amd64", c)
		_, arm := lookup(t, "arm64", c)
		if !amd && !arm {
			t.Errorf("control %q is not a call on either architecture", c)
		}
	}
}

// A foreign ABI and the x32 range are refused for every call number; the
// native ABI's unlisted numbers are allowed.
func TestArchAndX32AndSweep(t *testing.T) {
	foreign := []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_ARM, unix.AUDIT_ARCH_X86_64, unix.AUDIT_ARCH_AARCH64, 0, 0xffffffff}
	for _, an := range bothArches {
		arch := archOf(an)
		prog := build(t, arch, Table, Options{})
		listed := map[uint32]bool{}
		conditional := map[uint32]bool{}
		for _, r := range Table {
			if n := arch.nr(r); n != NoNr {
				listed[n] = true
				if len(r.Any) > 0 {
					conditional[n] = true
				}
			}
		}
		for nr := uint32(0); nr < 700; nr++ {
			for _, fa := range foreign {
				if fa == arch.Audit {
					continue
				}
				v, _ := run(prog, seccompData{Nr: int32(nr), Arch: fa}) //nolint:gosec // test arithmetic on small bounded values
				if v != retErrno(unix.EPERM) {
					t.Fatalf("%s: foreign arch %#x call %d: %s, want EPERM", an, fa, nr, verdictName(v))
				}
			}
			v, _ := run(prog, sd(arch, nr, a(0, 0, 0)))
			switch {
			case conditional[nr]:
				// refused only for some arguments; all-zero ones are allowed
			case listed[nr] && v == retAllow:
				t.Fatalf("%s: listed call %d is allowed", an, nr)
			case !listed[nr] && v != retAllow:
				t.Fatalf("%s: unlisted call %d: %s, want ALLOW", an, nr, verdictName(v))
			}
		}
		if an == nameAmd64 {
			for _, nr := range []uint32{0, 1, 39, 0x3fffffff, 0x40000000, 0x40000000 | 39, 0x40000000 | 41, 0x7fffffff, 0xffffffff} {
				v, _ := run(prog, sd(arch, nr, a()))
				if nr >= 0x40000000 && v != retErrno(unix.EPERM) {
					t.Fatalf("x32 call %#x: %s, want EPERM", nr, verdictName(v))
				}
				if nr < 0x40000000 && (nr == 0 || nr == 1 || nr == 39 || nr == 0x3fffffff) && v != retAllow {
					t.Fatalf("native call %#x: %s, want ALLOW", nr, verdictName(v))
				}
			}
		}
	}
}

// MUTATION CHECK, built into the suite: every rule and every clause of Table
// must be load-bearing, that is, dropping it changes at least one answer of
// the hand-written spec under at least one option set. A rule nobody tested
// fails here.
func TestEveryRuleAndClauseIsLoadBearing(t *testing.T) {
	answers := func(an string, table []Rule) map[string]string {
		all := map[string]string{}
		for _, os := range optionSets {
			_, res := evalSpec(t, an, build(t, archOf(an), table, os.opts), os.opts)
			for k, v := range res {
				all[os.name+"/"+k] = v
			}
		}
		return all
	}
	for _, an := range bothArches {
		arch := archOf(an)
		base := answers(an, Table)
		mutate := func(label string, table []Rule) {
			res := answers(an, table)
			for k, v := range base {
				if res[k] != v {
					return // the spec noticed
				}
			}
			t.Errorf("%s: %s can be removed and no spec probe changes", an, label)
		}
		for i, r := range Table {
			if arch.nr(r) == NoNr {
				continue
			}
			mutate("rule "+r.Name, append(append([]Rule{}, Table[:i]...), Table[i+1:]...))
			for ci := range r.Any {
				table := append([]Rule{}, Table...)
				mut := r
				mut.Any = append(append([]Clause{}, r.Any[:ci]...), r.Any[ci+1:]...)
				if len(mut.Any) == 0 {
					table = append(append([]Rule{}, Table[:i]...), Table[i+1:]...)
				} else {
					table[i] = mut
				}
				mutate(fmt.Sprintf("clause %d of %s", ci, r.Name), table)
			}
		}
		if arch.X32 {
			noX32 := arch
			noX32.X32 = false
			prog, _ := Build(noX32, Table)
			if v, _ := run(prog, sd(arch, 0x40000000|39, a())); v == retErrno(unix.EPERM) {
				t.Errorf("%s: without the x32 check the x32 number is still refused", an)
			}
		}
	}
}

// Options remove exactly the rules they name and nothing else.
func TestOptionsLiftOnlyTheirOwnRules(t *testing.T) {
	count := func(o Options) int { return len(Rules(o)) }
	var userns, debug int
	for _, r := range Table {
		switch r.Lift {
		case LiftUserNS:
			userns++
		case LiftDebug:
			debug++
		}
	}
	if userns == 0 || debug == 0 {
		t.Fatalf("an opt-out lifts nothing (userns %d, debug %d)", userns, debug)
	}
	if got := count(Options{}); got != len(Table) {
		t.Errorf("default keeps %d of %d rules", got, len(Table))
	}
	if got := count(Options{AllowUserNamespaces: true}); got != len(Table)-userns {
		t.Errorf("-allow-user-namespaces keeps %d rules, want %d", got, len(Table)-userns)
	}
	if got := count(Options{AllowDebuggers: true}); got != len(Table)-debug {
		t.Errorf("-allow-debuggers keeps %d rules, want %d", got, len(Table)-debug)
	}
	if got := count(Options{AllowUserNamespaces: true, AllowDebuggers: true}); got != len(Table)-userns-debug {
		t.Errorf("both keep %d rules, want %d", got, len(Table)-userns-debug)
	}
	// the opt-outs never reach the rules that must stay
	for _, r := range Rules(Options{AllowUserNamespaces: true, AllowDebuggers: true}) {
		if r.Lift != LiftNone {
			t.Errorf("rule %s kept with a lift", r.Name)
		}
	}
	for _, must := range []string{"clone3", "setns", "io_uring_setup", "bpf", "userfaultfd", "socket", "pidfd_getfd", "kexec_load"} {
		found := false
		for _, r := range Rules(Options{AllowUserNamespaces: true, AllowDebuggers: true}) {
			found = found || r.Name == must
		}
		if !found {
			t.Errorf("%s is lifted by an opt-out", must)
		}
	}
}

// --- jump arithmetic -------------------------------------------------------

// N unconditional rules: valid and correct up to the kernel's instruction
// cap, an error (never a silent wrap) beyond it. An earlier layout patched
// its offsets with a byte() cast that wrapped past 255 instructions.
func TestBuildScalesToTheKernelLimit(t *testing.T) {
	synth := func(n int) []Rule {
		rs := make([]Rule, n)
		for i := range rs {
			rs[i] = Rule{Name: fmt.Sprintf("r%d", i), Amd64: NoNr, Arm64: uint32(i + 1), Errno: unix.EPERM} //nolint:gosec // test arithmetic on small bounded values
		}
		return rs
	}
	for _, n := range []int{1, 60, 127, 128, 129, 254, 255, 256, 257, 300, 1000, 2000} {
		prog, err := Build(Arm64, synth(n))
		if err != nil {
			t.Fatalf("%d rules: %v", n, err)
		}
		if err := validate(prog); err != nil {
			t.Fatalf("%d rules: %v", n, err)
		}
		for _, nr := range []uint32{1, uint32(n) / 2, uint32(n), uint32(n) + 1, 5000} { //nolint:gosec // test arithmetic on small bounded values
			v, _ := run(prog, sd(Arm64, nr, a()))
			listed := nr >= 1 && nr <= uint32(n) //nolint:gosec // test arithmetic on small bounded values
			if listed != (v == retErrno(unix.EPERM)) {
				t.Fatalf("%d rules, call %d: %s", n, nr, verdictName(v))
			}
		}
	}
	if _, err := Build(Arm64, synth(2100)); err == nil {
		t.Error("2100 rules (4200 instructions) built; the kernel takes 4096")
	}
}

func TestBuildRefusesWhatItCannotAssemble(t *testing.T) {
	cases := map[string]struct {
		arch  Arch
		rules []Rule
	}{
		"duplicate number":   {Arm64, []Rule{{Name: "x", Arm64: 5, Errno: unix.EPERM}, {Name: "y", Arm64: 5, Errno: unix.EPERM}}},
		"x32 range":          {Amd64, []Rule{{Name: "x", Amd64: 0x40000001, Arm64: 1, Errno: unix.EPERM}}},
		"empty clause":       {Arm64, []Rule{{Name: "x", Arm64: 5, Errno: unix.EPERM, Any: []Clause{{}}}}},
		"argument 6":         {Arm64, []Rule{{Name: "x", Arm64: 5, Errno: unix.EPERM, Any: []Clause{{Terms: []Term{{Arg: 6, Op: OpEq}}}}}}},
		"unknown op":         {Arm64, []Rule{{Name: "x", Arm64: 5, Errno: unix.EPERM, Any: []Clause{{Terms: []Term{{Arg: 0, Op: 9}}}}}}},
		"block over 255 ops": {Arm64, []Rule{{Name: "x", Arm64: 5, Errno: unix.EPERM, Any: manyClauses(130)}}}, // 261 instructions
	}
	for name, c := range cases {
		if _, err := Build(c.arch, c.rules); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	if _, err := Build(Arch{}, nil); err == nil {
		t.Error("built with no audit architecture")
	}
}

func manyClauses(n int) []Clause {
	cs := make([]Clause, n)
	for i := range cs {
		cs[i] = Clause{Terms: []Term{{Arg: 0, Op: OpEq, Val: uint32(i)}}} //nolint:gosec // test arithmetic on small bounded values
	}
	return cs
}

// A long conditional block (up to the 255 limit) keeps correct jumps.
func TestLongArgumentBlocks(t *testing.T) {
	rules := []Rule{
		{Name: "front", Arm64: 1, Errno: unix.EPERM},
		{Name: "cond", Arm64: 2, Errno: unix.EAFNOSUPPORT, Any: manyClauses(60)}, // 60 clauses = 121 instructions
		{Name: "back", Arm64: 3, Errno: unix.ENOSYS},
		{Name: "cond2", Arm64: 4, Errno: unix.EPERM, Any: manyClauses(60)},
	}
	prog, err := Build(Arm64, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(prog); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		nr   uint32
		arg  uint64
		want string
	}{
		{1, 0, "EPERM"}, {2, 0, "EAFNOSUPPORT"}, {2, 59, "EAFNOSUPPORT"}, {2, 60, allow}, {2, 60 | 1<<40, allow}, {2, 7 | 1<<40, "EAFNOSUPPORT"},
		{3, 0, "ENOSYS"}, {4, 59, "EPERM"}, {4, 60, allow}, {5, 0, allow},
	} {
		v, _ := run(prog, sd(Arm64, c.nr, a(c.arg)))
		if got := verdictName(v); got != errnoName(c.want) {
			t.Errorf("call %d arg %d: %s, want %s", c.nr, c.arg, got, errnoName(c.want))
		}
	}
}

// --- differential: the assembler against a plain reading of the rules -------

// refVerdict is what a rule list means, evaluated directly on the data.
func refVerdict(arch Arch, rules []Rule, d seccompData) uint32 {
	if d.Arch != arch.Audit {
		return retErrno(unix.EPERM)
	}
	if arch.X32 && uint32(d.Nr) >= x32Bit { //nolint:gosec // test arithmetic on small bounded values
		return retErrno(unix.EPERM)
	}
	for _, r := range rules {
		if arch.nr(r) != uint32(d.Nr) { //nolint:gosec // test arithmetic on small bounded values
			continue
		}
		if len(r.Any) == 0 {
			return retErrno(r.Errno)
		}
		for _, c := range r.Any {
			ok := true
			for _, tm := range c.Terms {
				lo := uint32(d.Args[tm.Arg]) //nolint:gosec // test arithmetic on small bounded values
				switch tm.Op {
				case OpEq:
					ok = ok && lo == tm.Val
				case OpNe:
					ok = ok && lo != tm.Val
				case OpSet:
					ok = ok && lo&tm.Val != 0
				}
			}
			if ok {
				e := c.Errno
				if e == 0 {
					e = r.Errno
				}
				return retErrno(e)
			}
		}
		return retAllow
	}
	return retAllow
}

func TestAssemblerAgreesWithAPlainReading(t *testing.T) {
	rng := rand.New(rand.NewSource(20261022)) //nolint:gosec // a seeded generator for a reproducible differential test
	errnos := []unix.Errno{unix.EPERM, unix.ENOSYS, unix.EAFNOSUPPORT, unix.EPROTONOSUPPORT, unix.EACCES}
	vals := []uint32{0, 1, 2, 3, 0x10, 0x80, 0x100, 0x7e020000, 0x80000000, 0xffffffff}
	for round := 0; round < 400; round++ {
		n := 1 + rng.Intn(12)
		var rules []Rule
		for i := 0; i < n; i++ {
			r := Rule{Name: fmt.Sprintf("r%d", i), Amd64: NoNr, Arm64: uint32(10 + i), Errno: errnos[rng.Intn(len(errnos))]} //nolint:gosec // test arithmetic on small bounded values
			if rng.Intn(3) > 0 {                                                                                             // two in three are conditional
				for c := 1 + rng.Intn(6); c > 0; c-- {
					cl := Clause{}
					if rng.Intn(3) == 0 {
						cl.Errno = errnos[rng.Intn(len(errnos))]
					}
					for tm := 1 + rng.Intn(4); tm > 0; tm-- {
						cl.Terms = append(cl.Terms, Term{Arg: rng.Intn(6), Op: Op(rng.Intn(3)), Val: vals[rng.Intn(len(vals))]}) //nolint:gosec // test arithmetic on small bounded values
					}
					r.Any = append(r.Any, cl)
				}
			}
			rules = append(rules, r)
		}
		prog, err := Build(Arm64, rules)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if err := validate(prog); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		for probe := 0; probe < 300; probe++ {
			d := seccompData{Nr: int32(8 + rng.Intn(n+4)), Arch: unix.AUDIT_ARCH_AARCH64} //nolint:gosec // test arithmetic on small bounded values
			for j := range d.Args {
				d.Args[j] = uint64(vals[rng.Intn(len(vals))])
				if rng.Intn(2) == 0 {
					d.Args[j] |= uint64(rng.Uint32()) << 32 // garbage high word
				}
			}
			got, err := run(prog, d)
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			if want := refVerdict(Arm64, rules, d); got != want {
				t.Fatalf("round %d: call %d args %x: program says %s, the rules say %s\nrules: %+v", round, d.Nr, d.Args, verdictName(got), verdictName(want), rules)
			}
		}
	}
}

//go:build linux

package boxseccomp

import "golang.org/x/sys/unix"

// Options are the two opt-outs. Both are off by default and are decided once,
// when the filter is installed: filters stack and the strictest wins, so
// nothing in the tree can loosen them later.
type Options struct {
	// AllowUserNamespaces lifts the refusal of new user, network, mount, pid,
	// uts, ipc and cgroup namespaces and, with it, the mount family. They
	// have to lift together: a mount call is only useful inside a namespace.
	// It brings back the tools that build their own sandbox out of
	// namespaces (Chromium's, bubblewrap, nix, rootless podman, unshare -r)
	// and the kernel attack surface a user namespace opens, so it is off.
	AllowUserNamespaces bool
	// AllowDebuggers lifts the refusal of ptrace, process_vm_readv,
	// process_vm_writev and perf_event_open (gdb, strace, rr, py-spy,
	// AddressSanitizer's leak check, perf). It brings back the routes one box
	// process has into another's memory.
	AllowDebuggers bool
}

// Rules returns Table without the rules o lifts.
func Rules(o Options) []Rule { return rulesFrom(Table, o) }

// rulesFrom is Rules over any table (the tests build from altered ones).
func rulesFrom(table []Rule, o Options) []Rule {
	out := make([]Rule, 0, len(table))
	for _, r := range table {
		if (r.Lift == LiftUserNS && o.AllowUserNamespaces) || (r.Lift == LiftDebug && o.AllowDebuggers) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Values the table tests, spelled out so the numbers can be read next to
// their names (the tests check them against x/sys and the kernel headers).
const (
	cloneNewNS     = 0x00020000
	cloneNewCgroup = 0x02000000
	cloneNewUTS    = 0x04000000
	cloneNewIPC    = 0x08000000
	cloneNewUser   = 0x10000000
	cloneNewPID    = 0x20000000
	cloneNewNet    = 0x40000000
	cloneNewTime   = 0x00000080 // unshare only: in clone this bit is the exit signal

	// every namespace clone(2) can create
	cloneNsMask = cloneNewNS | cloneNewCgroup | cloneNewUTS | cloneNewIPC | cloneNewUser | cloneNewPID | cloneNewNet

	afKey     = 15
	afNetlink = 16
	afPacket  = 17
	afRds     = 21
	afTipc    = 30
	afAlg     = 38
	afVsock   = 40

	nlXfrm      = 6
	nlAudit     = 9
	nlNetfilter = 12
	nlCrypto    = 21
)

func eq(arg int, v uint32) Term { return Term{Arg: arg, Op: OpEq, Val: v} }

// families: socket domains an agent never uses, each of which has carried a
// kernel bug that an unprivileged process could reach (AF_ALG: Copy Fail and
// CVE-2025-39964; AF_RDS: PinTheft; AF_KEY, AF_PACKET, AF_TIPC, AF_VSOCK:
// historical and current local escalations). The domain is argument 0.
func familyClauses() []Clause {
	fams := []uint32{afKey, afPacket, afRds, afTipc, afAlg, afVsock}
	c := make([]Clause, 0, len(fams))
	for _, f := range fams {
		c = append(c, Clause{Terms: []Term{eq(0, f)}})
	}
	return c
}

// netlinkClauses: a netlink socket is needed for routes and uevents (Go's net,
// node, Chromium and glibc all open NETLINK_ROUTE), so AF_NETLINK stays; four
// protocols that reach firewall, IPsec, audit and crypto code do not. The
// protocol is argument 2. A refused protocol answers as an absent one would.
func netlinkClauses() []Clause {
	protos := []uint32{nlXfrm, nlAudit, nlNetfilter, nlCrypto}
	c := make([]Clause, 0, len(protos))
	for _, p := range protos {
		c = append(c, Clause{Terms: []Term{eq(0, afNetlink), eq(2, p)}, Errno: unix.EPROTONOSUPPORT})
	}
	return c
}

// Table is the deny list. Numbers are explicit for BOTH architectures (a
// build for one has to be able to test the program for the other); the tests
// prove them against golang.org/x/sys.
//
// What is deliberately NOT here: splice, vmsplice, tee, sendfile and
// copy_file_range (Go's io.Copy between sockets fails hard without them),
// seccomp and prctl (tools install their own filters), landlock_*,
// memfd_create, execveat, and personality. AF_NETLINK as a whole stays open.
var Table = []Rule{
	// --- one box process reaching into another (docs/box.md section 8.1).
	// The first four have an opt-out for debuggers; the rest never.
	{Name: "ptrace", Amd64: 101, Arm64: 117, Errno: unix.EPERM, Lift: LiftDebug, Group: "gate"},
	{Name: "process_vm_readv", Amd64: 310, Arm64: 270, Errno: unix.EPERM, Lift: LiftDebug, Group: "gate"},
	{Name: "process_vm_writev", Amd64: 311, Arm64: 271, Errno: unix.EPERM, Lift: LiftDebug, Group: "gate"},
	{Name: "perf_event_open", Amd64: 298, Arm64: 241, Errno: unix.EPERM, Lift: LiftDebug, Group: "gate"},
	{Name: "pidfd_getfd", Amd64: 438, Arm64: 438, Errno: unix.EPERM, Group: "gate"},
	{Name: "kcmp", Amd64: 312, Arm64: 272, Errno: unix.EPERM, Group: "gate"},
	{Name: "process_madvise", Amd64: 440, Arm64: 440, Errno: unix.EPERM, Group: "gate"},

	// --- namespaces. clone3 keeps its flags in memory, which BPF cannot read,
	// so it is refused outright with ENOSYS: glibc, musl and Go then fall back
	// to clone(2), whose flags are argument 0 on both architectures. (With
	// EPERM instead, nearly every program fails to start a thread.)
	{Name: "clone3", Amd64: 435, Arm64: 435, Errno: unix.ENOSYS, Group: "ns"},
	{Name: "setns", Amd64: 308, Arm64: 268, Errno: unix.EPERM, Group: "ns"},
	{Name: "unshare", Amd64: 272, Arm64: 97, Errno: unix.EPERM, Lift: LiftUserNS, Group: "ns",
		Any: []Clause{{Terms: []Term{{Arg: 0, Op: OpSet, Val: cloneNsMask | cloneNewTime}}}}},
	{Name: "clone", Amd64: 56, Arm64: 220, Errno: unix.EPERM, Lift: LiftUserNS, Group: "ns",
		Any: []Clause{{Terms: []Term{{Arg: 0, Op: OpSet, Val: cloneNsMask}}}}},

	// --- sockets (see familyClauses and netlinkClauses)
	{Name: "socket", Amd64: 41, Arm64: 198, Errno: unix.EAFNOSUPPORT, Group: "net",
		Any: append(familyClauses(), netlinkClauses()...)},
	{Name: "socketpair", Amd64: 53, Arm64: 199, Errno: unix.EAFNOSUPPORT, Group: "net", Any: familyClauses()},

	// --- kernel facilities an agent does not need. io_uring answers ENOSYS,
	// which is what a kernel without it says, so libuv (node) and the like
	// fall back to their thread pools.
	{Name: "io_uring_setup", Amd64: 425, Arm64: 425, Errno: unix.ENOSYS, Group: "kernel"},
	{Name: "io_uring_enter", Amd64: 426, Arm64: 426, Errno: unix.ENOSYS, Group: "kernel"},
	{Name: "io_uring_register", Amd64: 427, Arm64: 427, Errno: unix.ENOSYS, Group: "kernel"},
	{Name: "bpf", Amd64: 321, Arm64: 280, Errno: unix.EPERM, Group: "kernel"},
	{Name: "userfaultfd", Amd64: 323, Arm64: 282, Errno: unix.EPERM, Group: "kernel"},
	{Name: "keyctl", Amd64: 250, Arm64: 219, Errno: unix.EPERM, Group: "kernel"},
	{Name: "add_key", Amd64: 248, Arm64: 217, Errno: unix.EPERM, Group: "kernel"},
	{Name: "request_key", Amd64: 249, Arm64: 218, Errno: unix.EPERM, Group: "kernel"},
	{Name: "kexec_load", Amd64: 246, Arm64: 104, Errno: unix.EPERM, Group: "kernel"},
	{Name: "kexec_file_load", Amd64: 320, Arm64: 294, Errno: unix.EPERM, Group: "kernel"},
	{Name: "init_module", Amd64: 175, Arm64: 105, Errno: unix.EPERM, Group: "kernel"},
	{Name: "finit_module", Amd64: 313, Arm64: 273, Errno: unix.EPERM, Group: "kernel"},
	{Name: "delete_module", Amd64: 176, Arm64: 106, Errno: unix.EPERM, Group: "kernel"},
	{Name: "reboot", Amd64: 169, Arm64: 142, Errno: unix.EPERM, Group: "kernel"},
	{Name: "open_by_handle_at", Amd64: 304, Arm64: 265, Errno: unix.EPERM, Group: "kernel"},
	{Name: "name_to_handle_at", Amd64: 303, Arm64: 264, Errno: unix.EPERM, Group: "kernel"},

	// --- the mount family: capability-gated anyway, and useful to an agent
	// only inside a namespace it made, so it lifts with the namespaces
	{Name: "mount", Amd64: 165, Arm64: 40, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "umount2", Amd64: 166, Arm64: 39, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "pivot_root", Amd64: 155, Arm64: 41, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "chroot", Amd64: 161, Arm64: 51, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "open_tree", Amd64: 428, Arm64: 428, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "open_tree_attr", Amd64: 467, Arm64: 467, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "move_mount", Amd64: 429, Arm64: 429, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "fsopen", Amd64: 430, Arm64: 430, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "fsconfig", Amd64: 431, Arm64: 431, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "fsmount", Amd64: 432, Arm64: 432, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "fspick", Amd64: 433, Arm64: 433, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},
	{Name: "mount_setattr", Amd64: 442, Arm64: 442, Errno: unix.EPERM, Lift: LiftUserNS, Group: "mount"},

	// --- capability-gated administration. Docker's default profile refuses
	// these for a container without the capability; they are here so every
	// tier answers the same and so a capability gained some other way has no
	// door.
	{Name: "swapon", Amd64: 167, Arm64: 224, Errno: unix.EPERM, Group: "admin"},
	{Name: "swapoff", Amd64: 168, Arm64: 225, Errno: unix.EPERM, Group: "admin"},
	{Name: "acct", Amd64: 163, Arm64: 89, Errno: unix.EPERM, Group: "admin"},
	{Name: "quotactl", Amd64: 179, Arm64: 60, Errno: unix.EPERM, Group: "admin"},
	{Name: "quotactl_fd", Amd64: 443, Arm64: 443, Errno: unix.EPERM, Group: "admin"},
	{Name: "lookup_dcookie", Amd64: 212, Arm64: 18, Errno: unix.EPERM, Group: "admin"},
	{Name: "syslog", Amd64: 103, Arm64: 116, Errno: unix.EPERM, Group: "admin"},
	{Name: "settimeofday", Amd64: 164, Arm64: 170, Errno: unix.EPERM, Group: "admin"},
	{Name: "clock_settime", Amd64: 227, Arm64: 112, Errno: unix.EPERM, Group: "admin"},
	{Name: "clock_adjtime", Amd64: 305, Arm64: 266, Errno: unix.EPERM, Group: "admin"},
	{Name: "adjtimex", Amd64: 159, Arm64: 171, Errno: unix.EPERM, Group: "admin"},
	{Name: "sethostname", Amd64: 170, Arm64: 161, Errno: unix.EPERM, Group: "admin"},
	{Name: "setdomainname", Amd64: 171, Arm64: 162, Errno: unix.EPERM, Group: "admin"},

	// --- x86 only: arm64 has no number for these, so its program omits them
	{Name: "modify_ldt", Amd64: 154, Arm64: NoNr, Errno: unix.EPERM, Group: "legacy"},
	{Name: "iopl", Amd64: 172, Arm64: NoNr, Errno: unix.EPERM, Group: "legacy"},
	{Name: "ioperm", Amd64: 173, Arm64: NoNr, Errno: unix.EPERM, Group: "legacy"},
}

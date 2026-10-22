//go:build linux

// Package boxseccomp is the seccomp filter every box agent runs under.
//
// The box (docs/box.md) already keeps the agent from the host by user, file
// system and network. This filter narrows what is left: the kernel itself,
// which tiers 1 and 2 share with the host. It refuses, for the agent and its
// whole process tree, the system calls and arguments that the privilege
// escalations and container escapes of 2025-2026 have gone through: new user
// and network namespaces (which hand out the capabilities most kernel
// bugs need), io_uring, bpf, userfaultfd, the key store, perf events, the
// socket families and netlink protocols an agent never uses, the mount
// family, kexec and module loading. It also refuses the ptrace-class calls
// one box process would use to reach into another (docs/box.md section 8.1).
//
// It is a deny list over a default of allow, hand-assembled classic BPF (no
// libseccomp, no cgo), applied after no_new_privs so an unprivileged process
// may install it and nothing in the tree can shed it. Filters stack: Docker's
// own profile in tier 2 stays in force and this one only adds to it.
//
// Two opt-outs exist because some real tools need what they refuse
// (Options). The package builds a program for either release architecture on
// either, so the tests can check both.
package boxseccomp

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// NoNr marks "this architecture has no such system call" (arm64 lacks the
// legacy x86 ones). 0 cannot be the marker: arm64's io_setup is call 0.
const NoNr = ^uint32(0)

// Op is one comparison of a seccomp_data argument. Only the LOW 32 bits of an
// argument are ever compared. The kernel truncates int arguments (socket's
// domain) to 32 bits and ignores or rejects the high half of flag words, so
// a rule that looked at the high half could be dodged with garbage there, and
// one that required it to be zero would turn away a sign-extended flag word.
type Op uint8

const (
	OpEq  Op = iota // arg == Val
	OpNe            // arg != Val
	OpSet           // arg & Val != 0
)

// Term is one test on argument Arg (0..5).
type Term struct {
	Arg int
	Op  Op
	Val uint32
}

// Clause is a conjunction of terms. A Rule denies when any of its clauses
// holds; the first that does picks the errno.
type Clause struct {
	Terms []Term
	Errno unix.Errno // 0: the rule's own
}

// Lift names the opt-out that removes a rule.
type Lift uint8

const (
	LiftNone   Lift = iota // always applied
	LiftUserNS             // Options.AllowUserNamespaces
	LiftDebug              // Options.AllowDebuggers
)

// Rule denies one system call, or, with Any, some argument values of it.
type Rule struct {
	Name         string
	Amd64, Arm64 uint32 // call numbers; NoNr where the architecture has none
	Any          []Clause
	Errno        unix.Errno
	Lift         Lift
	Group        string // for people and for tests
}

// Arch is the ABI a program is built for.
type Arch struct {
	Name  string
	Audit uint32 // AUDIT_ARCH_*
	X32   bool   // amd64: refuse the x32 ABI (call numbers with bit 30 set)
}

const (
	nameAmd64 = "amd64"
	nameArm64 = "arm64"
)

var (
	Amd64 = Arch{Name: nameAmd64, Audit: unix.AUDIT_ARCH_X86_64, X32: true}
	Arm64 = Arch{Name: nameArm64, Audit: unix.AUDIT_ARCH_AARCH64}
)

// ArchFor returns the Arch for a GOARCH value; only the box's release
// architectures have one.
func ArchFor(goarch string) (Arch, bool) {
	switch goarch {
	case nameAmd64:
		return Amd64, true
	case nameArm64:
		return Arm64, true
	}
	return Arch{}, false
}

func (a Arch) nr(r Rule) uint32 {
	if a.Name == nameAmd64 {
		return r.Amd64
	}
	return r.Arm64
}

// classic-BPF encodings, spelled with x/sys' names so a typo cannot hide
const (
	opLdAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	opJeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	opJge   = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	opJset  = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	opRet   = unix.BPF_RET | unix.BPF_K

	// struct seccomp_data { int nr; u32 arch; u64 ip; u64 args[6]; }, little
	// endian on both release architectures; args[i]'s low word is at
	// offArgs+8*i
	offNr   = 0
	offArch = 4
	offArgs = 16

	// the x32 ABI reuses AUDIT_ARCH_X86_64 with this bit set on the call
	// number; the box is 64-bit, so that ABI is refused wholesale
	x32Bit = 0x40000000

	retAllow = unix.SECCOMP_RET_ALLOW
)

func retErrno(e unix.Errno) uint32 {
	return unix.SECCOMP_RET_ERRNO | (uint32(e) & unix.SECCOMP_RET_DATA)
}

type insn = unix.SockFilter

// Build assembles the program for a from rules. Layout:
//
//	arch != native      -> EPERM          (a foreign ABI, including i386 and
//	                                       its socketcall, could carry other
//	                                       numbers for the same call)
//	nr >= 0x40000000    -> EPERM          (amd64 only: the x32 ABI)
//	per unconditional rule:  JEQ nr, +0, +1 ; RET errno
//	per conditional rule:    JEQ nr, +0, +len(block) ; block
//	  block = per clause: (LD arg ; Jcc term, +0 or +skip)* ; RET errno
//	          then RET ALLOW
//	RET ALLOW
//
// Every deny RET sits right behind its own test, so no jump is longer than
// one rule's block and the 8-bit Jt/Jf fields cannot overflow however many
// rules there are; only the kernel's 4096-instruction cap limits N. An older
// layout with one shared deny at the end patched its offsets with a byte()
// cast that silently wrapped past 255 instructions and would have let rule
// 0 through. Build returns an error instead of truncating.
//
// Unconditional rules come first and load no argument, so the kernel can
// cache them (and every call no rule names) as "always allowed" without
// running the program again; arguments are loaded only inside a rule's own
// block, after its number matched.
func Build(a Arch, rules []Rule) ([]insn, error) {
	if a.Audit == 0 {
		return nil, errors.New("boxseccomp: no audit architecture")
	}
	seen := map[uint32]string{}
	for _, r := range rules {
		n := a.nr(r)
		if n == NoNr {
			continue
		}
		if n >= x32Bit {
			return nil, fmt.Errorf("boxseccomp: %s: call number %#x is in the x32 range", r.Name, n)
		}
		if prev, dup := seen[n]; dup {
			return nil, fmt.Errorf("boxseccomp: %s and %s are both call %d on %s", prev, r.Name, n, a.Name)
		}
		seen[n] = r.Name
	}

	var p []insn
	jump := func(code uint16, k uint32, jt, jf int) error {
		if jt < 0 || jt > 255 || jf < 0 || jf > 255 {
			return fmt.Errorf("jump (+%d,+%d) does not fit in 8 bits", jt, jf)
		}
		p = append(p, insn{Code: code, K: k, Jt: uint8(jt), Jf: uint8(jf)}) //nolint:gosec // both are within 0..255, checked above
		return nil
	}
	ld := func(off uint32) { p = append(p, insn{Code: opLdAbs, K: off}) }
	ret := func(v uint32) { p = append(p, insn{Code: opRet, K: v}) }

	ld(offArch)
	if err := jump(opJeq, a.Audit, 1, 0); err != nil {
		return nil, err
	}
	ret(retErrno(unix.EPERM))
	ld(offNr)
	if a.X32 {
		if err := jump(opJge, x32Bit, 0, 1); err != nil {
			return nil, err
		}
		ret(retErrno(unix.EPERM))
	}
	for _, r := range rules {
		if n := a.nr(r); n != NoNr && len(r.Any) == 0 {
			if err := jump(opJeq, n, 0, 1); err != nil {
				return nil, fmt.Errorf("%s: %w", r.Name, err)
			}
			ret(retErrno(r.Errno))
		}
	}
	for _, r := range rules {
		n := a.nr(r)
		if n == NoNr || len(r.Any) == 0 {
			continue
		}
		block, err := argBlock(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name, err)
		}
		if err := jump(opJeq, n, 0, len(block)); err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name, err)
		}
		p = append(p, block...)
	}
	ret(retAllow)
	if len(p) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("boxseccomp: %d instructions; the kernel takes at most %d", len(p), unix.BPF_MAXINSNS)
	}
	return p, nil
}

// argBlock is the code that runs once a conditional rule's call number has
// matched: it returns the rule's errno if a clause holds and ALLOW otherwise
// (the argument loads clobber A, so control must never fall back into the
// number tests).
func argBlock(r Rule) ([]insn, error) {
	n := 1 // the closing RET ALLOW
	for _, c := range r.Any {
		n += 2*len(c.Terms) + 1
	}
	b := make([]insn, 0, n)
	for ci, c := range r.Any {
		if len(c.Terms) == 0 {
			return nil, fmt.Errorf("clause %d has no terms (make it an unconditional rule)", ci)
		}
		m := len(c.Terms)
		for j, t := range c.Terms {
			if t.Arg < 0 || t.Arg > 5 {
				return nil, fmt.Errorf("clause %d: argument %d", ci, t.Arg)
			}
			b = append(b, insn{Code: opLdAbs, K: uint32(offArgs + 8*t.Arg)}) //nolint:gosec // t.Arg is 0..5, checked above; the low word only
			skip := 2*(m-j) - 1                                              // to the first insn behind this clause's RET
			if skip > 255 {
				return nil, fmt.Errorf("clause %d is too long", ci)
			}
			switch t.Op {
			case OpEq:
				b = append(b, insn{Code: opJeq, K: t.Val, Jt: 0, Jf: uint8(skip)}) //nolint:gosec // skip <= 255, checked above
			case OpNe:
				b = append(b, insn{Code: opJeq, K: t.Val, Jt: uint8(skip), Jf: 0}) //nolint:gosec // skip <= 255, checked above
			case OpSet:
				b = append(b, insn{Code: opJset, K: t.Val, Jt: 0, Jf: uint8(skip)}) //nolint:gosec // skip <= 255, checked above
			default:
				return nil, fmt.Errorf("clause %d: unknown op %d", ci, t.Op)
			}
		}
		e := c.Errno
		if e == 0 {
			e = r.Errno
		}
		b = append(b, insn{Code: opRet, K: retErrno(e)})
	}
	b = append(b, insn{Code: opRet, K: retAllow})
	if len(b) > 255 {
		return nil, fmt.Errorf("the argument block is %d instructions; a jump over it would not fit in 8 bits", len(b))
	}
	return b, nil
}

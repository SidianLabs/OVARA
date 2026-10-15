//go:build linux

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The command gate reads a program's arguments from the kernel at its exec
// stop and shows them to a person. One gap remained (docs/box.md §8): another
// process of the same agent could reach into the stopped program's memory and
// rewrite its arguments after they were read and approved but before the
// program used them. The ways one process writes another's memory all need
// the ptrace-class syscalls — process_vm_writev, or ptrace's own poke — and a
// box process has no capability that would let it reach outside the box, so
// the only target is a sibling in the same box.
//
// installBoxSeccomp refuses those syscalls (and process_vm_readv, so one box
// process cannot read another's memory either) for the agent and, because the
// filter is inherited across fork and exec, its whole tree. The agent runs
// with no_new_privs already set, so an unprivileged process may install the
// filter and nothing in the tree can shed it. The gate's tracer is a separate
// process on the host and is unaffected: it is not in this tree.
//
// A consequence, by design: a debugger run inside the box (gdb, strace) will
// get EPERM. The box is a sandbox, not a debugging environment; that trade is
// the point of closing the gap.
func installBoxSeccomp() error {
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		auditArch = unix.AUDIT_ARCH_AARCH64
	default:
		// Only the box's release architectures are handled; on anything
		// else the gap stays open rather than installing a filter that
		// might be wrong for an untested ABI.
		return nil
	}

	const (
		// classic-BPF opcodes (linux/bpf_common.h)
		bpfLdW   = 0x20 // BPF_LD | BPF_W | BPF_ABS
		bpfJmpEq = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
		bpfJmpGe = 0x35 // BPF_JMP | BPF_JGE | BPF_K
		bpfRet   = 0x06 // BPF_RET | BPF_K

		// seccomp_data field offsets
		offNr   = 0
		offArch = 4

		// the x32 ABI reuses AUDIT_ARCH_X86_64 with this bit set on the
		// syscall number; the box is 64-bit, so deny that ABI wholesale
		x32Bit = 0x40000000

		retAllow = 0x7fff0000 // SECCOMP_RET_ALLOW
		retDeny  = 0x00050001 // SECCOMP_RET_ERRNO | EPERM(1)
	)

	// Build the program, then fix up jump offsets so every "this is a
	// blocked syscall" test jumps to the single deny instruction at the end.
	type insn = unix.SockFilter
	prog := []insn{
		{Code: bpfLdW, K: offArch},
		// if arch != native, deny (a foreign ABI could carry a different
		// syscall number for the same call); patched below
		{Code: bpfJmpEq, K: auditArch, Jt: 0, Jf: 0},
		{Code: bpfLdW, K: offNr},
	}
	if runtime.GOARCH == "amd64" {
		prog = append(prog, insn{Code: bpfJmpGe, K: x32Bit}) // x32 ABI -> deny
	}
	blocked := []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV}
	for _, nr := range blocked {
		prog = append(prog, insn{Code: bpfJmpEq, K: nr}) // == blocked -> deny
	}
	prog = append(prog,
		insn{Code: bpfRet, K: retAllow},
		insn{Code: bpfRet, K: retDeny}, // the deny instruction
	)
	deny := len(prog) - 1

	// Patch jump targets now that the layout is fixed. The arch check denies
	// on mismatch (Jf); every other test denies on match (Jt). Offsets are
	// the number of instructions to skip, so they stay valid for both arches.
	// The program is a dozen instructions, so every offset fits in a uint8.
	for i := range prog {
		off := byte(deny - i - 1)
		switch {
		case prog[i].Code == bpfJmpEq && prog[i].K == auditArch:
			prog[i].Jf = off
		case prog[i].Code == bpfJmpGe || prog[i].Code == bpfJmpEq:
			prog[i].Jt = off
		}
	}

	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]} //nolint:gosec // a fixed dozen-instruction program
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_SET_MODE_FILTER), 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("installing the box seccomp filter: %w", errno)
	}
	return nil
}

//go:build linux

package boxseccomp

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// A small classic-BPF interpreter for the instructions seccomp programs use,
// written independently of Build: the tests run a built program on made-up
// seccomp_data and compare the answer with what the spec says.

// seccompData is struct seccomp_data.
type seccompData struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}

func (d seccompData) bytes() [64]byte {
	var b [64]byte
	binary.LittleEndian.PutUint32(b[0:], uint32(d.Nr)) //nolint:gosec // test arithmetic on small bounded values
	binary.LittleEndian.PutUint32(b[4:], d.Arch)
	binary.LittleEndian.PutUint64(b[8:], d.IP)
	for i, a := range d.Args {
		binary.LittleEndian.PutUint64(b[16+8*i:], a)
	}
	return b
}

// validate applies the checks the kernel's classic-BPF verifier and
// seccomp_check_filter make: only the instructions seccomp allows, loads
// from aligned offsets inside seccomp_data, every jump forward and inside the
// program, and a program that ends in RET so no path falls off the end.
func validate(p []unix.SockFilter) error {
	if len(p) == 0 || len(p) > unix.BPF_MAXINSNS {
		return fmt.Errorf("program length %d", len(p))
	}
	for i, in := range p {
		switch in.Code {
		case opLdAbs:
			if in.K%4 != 0 || in.K > 60 {
				return fmt.Errorf("insn %d: bad seccomp_data offset %d", i, in.K)
			}
		case opJeq, opJge, opJset:
			if i+1+int(in.Jt) >= len(p) || i+1+int(in.Jf) >= len(p) {
				return fmt.Errorf("insn %d: jump out of the program (jt %d jf %d, len %d)", i, in.Jt, in.Jf, len(p))
			}
		case opRet:
		default:
			return fmt.Errorf("insn %d: opcode %#x is not one this filter uses", i, in.Code)
		}
	}
	if p[len(p)-1].Code != opRet {
		return fmt.Errorf("the program does not end in RET")
	}
	return nil
}

// run interprets p on d and returns the seccomp action word.
func run(p []unix.SockFilter, d seccompData) (uint32, error) {
	data := d.bytes()
	var acc uint32
	for pc := 0; pc < len(p); {
		in := p[pc]
		pc++
		switch in.Code {
		case opLdAbs:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case opJeq, opJge, opJset:
			var hit bool
			switch in.Code {
			case opJeq:
				hit = acc == in.K
			case opJge:
				hit = acc >= in.K
			case opJset:
				hit = acc&in.K != 0
			}
			if hit {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case opRet:
			return in.K, nil
		default:
			return 0, fmt.Errorf("opcode %#x at %d", in.Code, pc-1)
		}
		if pc >= len(p) {
			return 0, fmt.Errorf("fell off the end of the program")
		}
	}
	return 0, fmt.Errorf("no RET")
}

// verdictName names an action word: ALLOW, or the errno of an ERRNO action.
func verdictName(v uint32) string {
	switch v & unix.SECCOMP_RET_ACTION_FULL {
	case unix.SECCOMP_RET_ALLOW:
		return "ALLOW"
	case unix.SECCOMP_RET_ERRNO:
		return unix.Errno(v & unix.SECCOMP_RET_DATA).Error()
	}
	return fmt.Sprintf("%#x", v)
}

// Package vm runs an Ovara box inside a Linux virtual machine, for hosts
// whose kernel cannot run the box itself (macOS through Lima, Windows
// through WSL2) and, later, for the microVM tier on Linux (docs/box.md
// §4.4, §10).
//
// The rule every driver keeps (box.md §10): Ovara and its keys stay on the
// host; the VM's only network path is to Ovara's proxy (and the command
// gate) on the host; the workspace is a copy inside the VM, never a mount;
// changes come back by copying out and going through the host's commit-back.
// A driver that cannot show the network rule holds, from inside the VM,
// refuses to run the agent (Verify).
package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Driver starts and drives one kind of VM.
type Driver interface {
	// Name is the driver's name as `ovara box -vm` takes it.
	Name() string
	// Create makes and starts a VM from spec, provisioned with the network
	// lockdown. It returns once the VM is up.
	Create(ctx context.Context, spec Spec) error
	// Verify checks from inside the VM that the lockdown is in place and
	// that a direct connection to the outside fails. Callers run the agent
	// only after it returns nil.
	Verify(ctx context.Context, name string) error
	// CopyIn copies a host file or directory into the VM.
	CopyIn(ctx context.Context, name, hostSrc, guestDst string) error
	// CopyOut copies a file or directory out of the VM.
	CopyOut(ctx context.Context, name, guestSrc, hostDst string) error
	// Run runs argv inside the VM and returns its exit status.
	Run(ctx context.Context, name string, argv []string, stdio Stdio) (int, error)
	// Delete stops and removes the VM and its disk.
	Delete(ctx context.Context, name string) error
}

// Stdio is the agent's terminal, passed through to a command in the VM.
type Stdio struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Spec is one VM.
type Spec struct {
	Name      string // ovara-<...>; see ValidName
	CPUs      int
	MemoryGiB int
	DiskGiB   int
	// ProxyPort and GatePort are the host ports the VM may reach: Ovara's
	// proxy and the box's command gate. Nothing else on the host or beyond.
	ProxyPort int
	GatePort  int
}

var nameRE = regexp.MustCompile(`^ovara-[a-z0-9][a-z0-9-]{0,38}$`)

// ValidName reports whether name is a VM name Ovara creates: "ovara-"
// then lower-case letters, digits and dashes. The prefix keeps Ovara from
// ever touching a VM it did not make.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Validate checks a spec before anything is created.
func (s Spec) Validate() error {
	if !ValidName(s.Name) {
		return fmt.Errorf("vm name %q: want ovara-<lower-case letters, digits, dashes>", s.Name)
	}
	if s.CPUs < 1 || s.CPUs > 64 {
		return fmt.Errorf("vm cpus %d: want 1-64", s.CPUs)
	}
	if s.MemoryGiB < 1 || s.MemoryGiB > 256 {
		return fmt.Errorf("vm memory %d GiB: want 1-256", s.MemoryGiB)
	}
	if s.DiskGiB < 8 || s.DiskGiB > 2048 {
		return fmt.Errorf("vm disk %d GiB: want 8-2048", s.DiskGiB)
	}
	for _, p := range []int{s.ProxyPort, s.GatePort} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("vm host port %d: want 1-65535", p)
		}
	}
	if s.ProxyPort == s.GatePort {
		return errors.New("vm proxy and gate ports must differ")
	}
	return nil
}

//go:build linux

package contain

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock ABI v1: all filesystem rights the ABI knows about
// (except REFER — only needed for reparenting, never granted). We grant
// the same set under each allowed dir; anything outside them is denied
// by omission. x/sys v0.13 ships the syscall numbers + structs but not
// the wrappers, so we call them directly.
const (
	rulePathBeneath        = 1
	versionFlag            = 1 << 0 // LANDLOCK_CREATE_RULESET_VERSION
	allFSRights     uint64 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
)

type landlockBackend struct{}

// probeABI returns the best Landlock ABI the kernel supports (0=none).
// The VERSION query requires attr=NULL and size=0 per the API contract;
// kernels that enforce it return EINVAL for the attr-carrying form,
// which falsely reports Landlock as unavailable (H9 apparatus defect A1).
func probeABI() int {
	r1, _, e1 := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, versionFlag)
	if e1 != 0 {
		return 0
	}
	return int(r1)
}

var probe = struct {
	once  sync.Once
	avail bool
}{}

func (landlockBackend) Name() string { return "landlock" }

func (landlockBackend) Available() bool {
	probe.once.Do(func() { probe.avail = probeABI() >= 1 })
	return probe.avail
}

func (l landlockBackend) ApplyFS(allowedDirs []string) error {
	if !l.Available() {
		return ErrUnsupported
	}
	var attr unix.LandlockRulesetAttr
	attr.Access_fs = allFSRights
	fd, _, e1 := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e1 != 0 {
		return fmt.Errorf("landlock create_ruleset: %w", e1)
	}
	defer unix.Close(int(fd))

	for _, dir := range allowedDirs {
		dfd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("landlock open %s: %w", dir, err)
		}
		ra := unix.LandlockPathBeneathAttr{
			Allowed_access: allFSRights,
			Parent_fd:      int32(dfd),
		}
		_, _, e2 := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd,
			rulePathBeneath, uintptr(unsafe.Pointer(&ra)), 0, 0, 0)
		unix.Close(dfd)
		if e2 != 0 {
			return fmt.Errorf("landlock add_rule %s: %w", dir, e2)
		}
	}
	// no_new_privs is required before restrict_self.
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return fmt.Errorf("prctl no_new_privs: %w", e)
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return fmt.Errorf("landlock restrict_self: %w", e)
	}
	return nil
}

func newBackend() Enforcement { return landlockBackend{} }

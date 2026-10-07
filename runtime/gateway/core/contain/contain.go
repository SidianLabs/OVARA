// Package contain provides OS-mediated enforcement beneath the
// application-level decision engine. Axis-2 of the Phase-3 experiment
// matrix: the same attacker objectives replayed at increasing
// enforcement strength.
//
// The decision engine authorizes a canonical string; the kernel
// resolves that string to an object. Any resolution feature that can
// change object identity after authorization (symlinks, mount points,
// hardlinks, rename) is a boundary this layer exists to close.
package contain

import "errors"

// ErrUnsupported is returned on platforms without an OS enforcement
// backend (anything but Linux today).
var ErrUnsupported = errors.New("contain: no OS enforcement backend on this platform")

// Enforcement is one OS containment backend. Apply is irreversible
// for the calling thread — always call it in a dedicated worker
// process/thread, never in the gateway's serving path.
type Enforcement interface {
	// Name identifies the backend ("landlock", "none").
	Name() string
	// Available reports whether the running kernel supports this
	// backend (probe is cached; it does not alter caller state).
	Available() bool
	// ApplyFS restricts filesystem access to exactly the listed
	// directories (read+write+execute rights; everything else denied).
	// Irreversible.
	ApplyFS(allowedDirs []string) error
}

// New returns the platform's best available backend, or the none
// backend when the OS has none.
func New() Enforcement { return newBackend() }

// ProbeResult records one containment-level measurement for the
// experiment ledger.
type ProbeResult struct {
	Backend   string
	Available bool
	// WriteAllowed is the ground truth: did the filesystem actually
	// accept the write through the symlink? true under C-core
	// (boundary limitation), expected false under C+Landlock.
	WriteAllowed bool
	Err          string
}

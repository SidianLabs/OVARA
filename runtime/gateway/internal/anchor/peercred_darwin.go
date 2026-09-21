//go:build darwin

package anchor

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// macOS/BSD equivalent of Linux SO_PEERCRED: LOCAL_PEERCRED returns an
// xucred carrying the peer's uid. Same trust semantics — filesystem
// ownership is the boundary; does not protect against root.
func verifyPeerUID(conn net.Conn, want int) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix connection", ErrPinMismatch)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("anchor: LOCAL_PEERCRED: %w", err)
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return fmt.Errorf("anchor: LOCAL_PEERCRED: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("anchor: LOCAL_PEERCRED: %w", serr)
	}
	if int(cred.Uid) != want {
		return fmt.Errorf("%w: peer uid %d, pinned %d", ErrPinMismatch, cred.Uid, want)
	}
	return nil
}

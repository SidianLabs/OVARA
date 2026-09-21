//go:build linux

package anchor

import (
	"fmt"
	"net"
	"syscall"
)

func verifyPeerUID(conn net.Conn, want int) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix connection", ErrPinMismatch)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", err)
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", serr)
	}
	if int(cred.Uid) != want {
		return fmt.Errorf("%w: peer uid %d, pinned %d", ErrPinMismatch, cred.Uid, want)
	}
	return nil
}

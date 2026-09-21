//go:build !linux && !darwin

package anchor

import (
	"fmt"
	"net"
)

// No peer-credential API is wired for this platform. unix:// oracle
// transports fail closed; use https:// instead.
func verifyPeerUID(conn net.Conn, want int) error {
	return fmt.Errorf("%w: unix-socket oracle pins unsupported on this platform (use https://)", ErrUnavailable)
}
